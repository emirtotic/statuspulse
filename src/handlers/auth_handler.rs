use axum::{
    extract::{State, Form},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::{Deserialize, Serialize};
use crate::{services::auth_service::AuthService, AppState};
use crate::services::sendgrid_service::SendGridService;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    pub email: String,
    pub password: String,
    #[serde(rename = "g-recaptcha-response")]
    pub recaptcha_token: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "g-recaptcha-response")]
    pub recaptcha_token: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}

#[axum::debug_handler]
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LoginRequest>,
) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let secret = std::env::var("RECAPTCHA_SECRET_KEY").unwrap_or_default();

    let verify_res = client
        .post("https://www.google.com/recaptcha/api/siteverify")
        .form(&[
            ("secret", secret.as_str()),
            ("response", form.recaptcha_token.as_str()),
        ])
        .send()
        .await;

    let Ok(resp) = verify_res else {
        tracing::warn!("❌ reCAPTCHA HTTP request failed");
        let mut flash_cookie = Cookie::new("flash", "reCAPTCHA verification failed.");
        flash_cookie.set_path("/login");
        flash_cookie.set_max_age(time::Duration::seconds(5));
        return (jar.add(flash_cookie), Redirect::to("/login")).into_response();
    };

    let Ok(json) = resp.json::<serde_json::Value>().await else {
        tracing::warn!("❌ reCAPTCHA JSON decode failed");
        let mut flash_cookie = Cookie::new("flash", "reCAPTCHA verification failed.");
        flash_cookie.set_path("/login");
        flash_cookie.set_max_age(time::Duration::seconds(5));
        return (jar.add(flash_cookie), Redirect::to("/login")).into_response();
    };

    let success = json.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        tracing::warn!("❌ reCAPTCHA check failed: {:?}", json);
        let mut flash_cookie = Cookie::new("flash", "reCAPTCHA verification failed.");
        flash_cookie.set_path("/login");
        flash_cookie.set_max_age(time::Duration::seconds(5));
        return (jar.add(flash_cookie), Redirect::to("/login")).into_response();
    }

    // Dummy sendgrid instance
    let dummy_sendgrid = SendGridService::new("".into(), "".into());
    let auth_service = AuthService::new(&state.db, &state.jwt_secret, dummy_sendgrid);

    match auth_service.login_user(&form.email, &form.password).await {
        Ok(token) => {
            tracing::info!("✅ Login successful for {}", form.email);
            let mut auth_cookie = Cookie::new("auth_token", token);
            auth_cookie.set_path("/");
            auth_cookie.set_http_only(true);
            (jar.add(auth_cookie), Redirect::to("/")).into_response()
        }
        Err(err) => {
            tracing::warn!("❌ Login failed for {}: {:?}", form.email, err);
            let mut flash_cookie = Cookie::new("flash", "Invalid credentials");
            flash_cookie.set_path("/login");
            flash_cookie.set_max_age(time::Duration::seconds(5));
            (jar.add(flash_cookie), Redirect::to("/login")).into_response()
        }
    }
}

#[axum::debug_handler]
pub async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<RegisterRequest>,
) -> impl IntoResponse {

    let client = reqwest::Client::new();
    let secret = std::env::var("RECAPTCHA_SECRET_KEY").unwrap_or_default();

    let verify_res = client
        .post("https://www.google.com/recaptcha/api/siteverify")
        .form(&[
            ("secret", secret.as_str()),
            ("response", form.recaptcha_token.as_str()),
        ])
        .send()
        .await;

    let Ok(resp) = verify_res else {
        tracing::warn!("❌ reCAPTCHA HTTP request failed");
        let mut flash_cookie = Cookie::new("flash", "reCAPTCHA verification failed.");
        flash_cookie.set_path("/register");
        flash_cookie.set_max_age(time::Duration::seconds(5));
        return (jar.add(flash_cookie), Redirect::to("/register")).into_response();
    };

    let Ok(json) = resp.json::<serde_json::Value>().await else {
        tracing::warn!("❌ reCAPTCHA JSON decode failed");
        let mut flash_cookie = Cookie::new("flash", "reCAPTCHA verification failed.");
        flash_cookie.set_path("/register");
        flash_cookie.set_max_age(time::Duration::seconds(5));
        return (jar.add(flash_cookie), Redirect::to("/register")).into_response();
    };

    let success = json.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        tracing::warn!("❌ reCAPTCHA check failed: {:?}", json);
        let mut flash_cookie = Cookie::new("flash", "reCAPTCHA verification failed.");
        flash_cookie.set_path("/register");
        flash_cookie.set_max_age(time::Duration::seconds(5));
        return (jar.add(flash_cookie), Redirect::to("/register")).into_response();
    }

    let sendgrid_service = SendGridService::new(
        std::env::var("SENDGRID_API_KEY").expect("SENDGRID_API_KEY must be set").trim().to_string(),
        std::env::var("SENDGRID_FROM_EMAIL").expect("SENDGRID_FROM_EMAIL must be set").trim().to_string(),
    );

    let auth_service = AuthService::new(&state.db, &state.jwt_secret, sendgrid_service);

    match auth_service.register_user(&form.name, &form.email, &form.password).await {
        Ok(token) => {
            tracing::info!("✅ Registration successful for {}", form.email);
            let mut auth_cookie = Cookie::new("auth_token", token);
            auth_cookie.set_path("/");
            auth_cookie.set_http_only(true);
            (jar.add(auth_cookie), Redirect::to("/")).into_response()
        }
        Err(err) => {
            tracing::warn!("❌ Registration failed for {}: {:?}", form.email, err);
            let mut flash_cookie = Cookie::new("flash", "Registration failed.");
            flash_cookie.set_path("/register");
            flash_cookie.set_max_age(time::Duration::seconds(5));
            (jar.add(flash_cookie), Redirect::to("/register")).into_response()
        }
    }
}

