use axum_extra::response::Html;
use serde::{Deserialize, Serialize};
use tera::Tera;
use axum::{
    extract::{Form, State},
    response::{IntoResponse, Redirect},
    Extension,
};
use time::Duration;

use crate::{
    AppState,
    db::user_repository::UserRepository,
    utils::jwt_auth::decode_token,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::extract::Path;
use base64::encode;
use chrono::Utc;
use http::StatusCode;
use jsonwebtoken::{EncodingKey, Header};
use rand_core::OsRng;
use tracing::error;
use crate::services::auth_service::AuthService;
use crate::services::sendgrid_service::SendGridService;

#[derive(Deserialize)]
pub struct ChangePasswordForm {
    pub current_password: String,
    pub new_password: String,
    pub confirm_new_password: String,
}

#[derive(Deserialize)]
pub struct ForgotPasswordForm {
    pub email: String,
}

#[derive(Serialize, Deserialize)]
struct PasswordResetClaims {
    sub: u64, // user_id
    exp: usize,
}

#[derive(Deserialize)]
pub struct ResetPasswordForm {
    pub new_password: String,
    pub confirm_new_password: String,
}

#[axum::debug_handler]
pub async fn process_forgot_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<ForgotPasswordForm>,
) -> impl IntoResponse {
    let user_repo = UserRepository::new(&state.db);

    let user = match user_repo.get_by_email(&form.email).await {
        Ok(Some(u)) => u,
        _ => {
            // Nikad ne otkrivamo da li email postoji
            return redirect_with_flash(jar, "/forgot-password", "If that email exists, a reset link has been sent.").into_response();
        }
    };

    // create JWT token with 30 minutes duration
    let expiration = Utc::now() + chrono::Duration::minutes(30);
    let claims = PasswordResetClaims {
        sub: user.id,
        exp: expiration.timestamp() as usize,
    };

    let token = match jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    ) {
        Ok(token) => token,
        Err(err) => {
            error!("❌ Failed to create password reset token: {:?}", err);
            return redirect_with_flash(jar, "/forgot-password", "Something went wrong. Please try again.").into_response();
        }
    };

    // prepare email
    let reset_url = format!("http://localhost:3000/reset-password/{}", token);

    let sendgrid_service = SendGridService::new(
        std::env::var("SENDGRID_API_KEY").expect("SENDGRID_API_KEY must be set"),
        std::env::var("SENDGRID_FROM_EMAIL").expect("SENDGRID_FROM_EMAIL must be set"),
    );

    let email_result = sendgrid_service
        .send_alert(
            &user.email,
            "Reset Your Password",
            "src/services/email_templates/email_password_reset.html",
            &[("user_name", &user.name), ("reset_url", &reset_url)],
        )
        .await;

    if let Err(e) = email_result {
        error!("❌ Failed to send password reset email to {}: {:?}", user.email, e);
    } else {
        tracing::info!("✅ Sent password reset email to {}", user.email);
    }

    redirect_with_flash(jar, "/forgot-password", "If that email exists, a reset link has been sent.").into_response()
}


#[axum::debug_handler]
pub async fn change_password_form(
    Extension(tera): Extension<Tera>,
    jar: CookieJar,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let token = jar.get("auth_token").map(|c| c.value().to_string());

    let is_authenticated = token
        .as_ref()
        .and_then(|t| crate::utils::jwt_auth::decode_token(t, &state.jwt_secret).ok())
        .is_some();

    if !is_authenticated {
        return StatusCode::NOT_FOUND.into_response();
    }

    let mut ctx = tera::Context::new();

    if let Some(cookie) = jar.get("flash") {
        ctx.insert("flash", cookie.value());
    }

    let rendered = match tera.render("change_password.html", &ctx) {
        Ok(html) => html,
        Err(err) => {
            tracing::error!("Tera render error: {:?}", err);
            tera.render("error.html", &tera::Context::new()).unwrap_or_else(|_| "<h1>Error</h1>".to_string())
        }
    };

    Html(rendered).into_response()
}


#[axum::debug_handler]
pub async fn process_password_change(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<ChangePasswordForm>,
) -> impl IntoResponse {

    // Retrieve user from JWT cookie
    let token = match jar.get("auth_token") {
        Some(cookie) => cookie.value().to_string(),
        None => return Redirect::to("/login").into_response(),
    };

    let user_id = match decode_token(&token, &state.jwt_secret) {
        Ok(id) => id,
        Err(_) => return Redirect::to("/login").into_response(),
    };

    // validate password
    if form.new_password != form.confirm_new_password {
        return redirect_with_flash(jar, "/settings/change-password", "Passwords do not match").into_response();
    }

    // get user from db
    let user_repo = UserRepository::new(&state.db);
    let user = match user_repo.get_user_by_id(user_id).await {
        Ok(Some(u)) => u,
        _ => return redirect_with_flash(jar, "/settings/change-password", "Passwords do not match").into_response()
    };

    // check current password
    if !verify_password(&form.current_password, &user.password_hash) {
        return redirect_with_flash(jar, "/settings/change-password", "Passwords do not match").into_response();

    }

    // hash new password
    let new_hash = match hash_password(&form.new_password) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to hash password: {:?}", e);
            return redirect_with_flash(jar, "/settings/change-password", "Passwords do not match").into_response();

        }
    };

    // update password
    if let Err(e) = user_repo.update_password(user_id as i64, &new_hash).await {
        error!("Failed to update password: {:?}", e);
        return redirect_with_flash(jar, "/settings/change-password", "Passwords do not match").into_response();
    }

    // email notification
    let sendgrid_service = SendGridService::new(
        std::env::var("SENDGRID_API_KEY").expect("SENDGRID_API_KEY must be set"),
        std::env::var("SENDGRID_FROM_EMAIL").expect("SENDGRID_FROM_EMAIL must be set"),
    );
    let auth_service = AuthService::new(&state.db, &state.jwt_secret, sendgrid_service);

    if let Err(e) = auth_service
        .send_password_changed_email(&user.email, &user.name)
        .await
    {
        error!(
            "❌ Failed to send password changed confirmation email to {}: {:?}",
            &user.email, e
        );
    } else {
        tracing::info!("✅ Password changed and email sent to {}", &user.email);
    }

    redirect_with_flash(jar, "/dashboard", "Password changed successfully").into_response()
}

fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();
    Ok(hash)
}

fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

pub fn redirect_with_flash(jar: CookieJar, location: &str, message: &str) -> impl IntoResponse {
    let location_owned = location.to_string();

    let mut flash_cookie = Cookie::new("flash", message.to_string());
    flash_cookie.set_path(location_owned.clone());
    flash_cookie.set_max_age(Duration::seconds(5));

    (jar.add(flash_cookie), Redirect::to(&location_owned))
}

#[axum::debug_handler]
pub async fn process_reset_password(
    Path(token): Path<String>,
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<ResetPasswordForm>,
) -> impl IntoResponse {

    let claims = match jsonwebtoken::decode::<PasswordResetClaims>(
        &token,
        &jsonwebtoken::DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &jsonwebtoken::Validation::default(),
    ) {
        Ok(data) => data.claims,
        Err(e) => {
            error!("❌ Invalid or expired reset token: {:?}", e);
            return redirect_with_flash(jar, "/login", "Invalid or expired reset link.").into_response();
        }
    };

    if form.new_password != form.confirm_new_password {
        return redirect_with_flash(
            jar,
            &format!("/reset-password/{}", token),
            "Passwords do not match",
        )
            .into_response();
    }

    let new_hash = match hash_password(&form.new_password) {
        Ok(h) => h,
        Err(e) => {
            error!("❌ Failed to hash password: {:?}", e);
            return redirect_with_flash(jar, "/", "Something went wrong. Please try again.").into_response();
        }
    };

    let user_repo = UserRepository::new(&state.db);
    let user = match user_repo.get_user_by_id(claims.sub).await {
        Ok(Some(u)) => u,
        _ => {
            return redirect_with_flash(jar, "/", "User not found.").into_response();
        }
    };

    if let Err(e) = user_repo.update_password(user.id as i64, &new_hash).await {
        error!("❌ Failed to update password in DB: {:?}", e);
        return redirect_with_flash(jar, "/", "Failed to update password.").into_response();
    }

    let sendgrid_service = SendGridService::new(
        std::env::var("SENDGRID_API_KEY").expect("SENDGRID_API_KEY must be set"),
        std::env::var("SENDGRID_FROM_EMAIL").expect("SENDGRID_FROM_EMAIL must be set"),
    );

    if let Err(e) = sendgrid_service
        .send_password_changed_notification(&user.email, &user.name)
        .await
    {
        error!("❌ Failed to send password change email to {}: {:?}", user.email, e);
    } else {
        tracing::info!("✅ Password change email sent to {}", user.email);
    }

    redirect_with_flash(jar, "/login", "Password successfully updated. You can now sign in.")
        .into_response()
}


