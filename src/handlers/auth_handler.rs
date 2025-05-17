use axum::{
    extract::{State, Form},
    response::{IntoResponse, Redirect},
};
use serde::{Deserialize, Serialize};
use crate::{services::auth_service::AuthService, AppState};
use axum_extra::extract::cookie::{Cookie, CookieJar};

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    pub email: String,
    pub password: String,
    pub plan: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
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
    let auth_service = AuthService::new(&state.db, &state.jwt_secret);

    match auth_service.login_user(&form.email, &form.password).await {
        Ok(token) => {
            tracing::info!("✅ Login successful, issuing auth_token cookie");

            let mut auth_cookie = Cookie::new("auth_token", token);
            auth_cookie.set_path("/");
            auth_cookie.set_http_only(true);
            // ⚠️ Don't use .set_secure(true) on localhost HTTP
            // auth_cookie.set_secure(true);

            (jar.add(auth_cookie), Redirect::to("/dashboard"))
        }
        Err(err) => {
            tracing::warn!("❌ Login failed: {:?}", err);

            let mut flash_cookie = Cookie::new("flash", "Invalid credentials");
            flash_cookie.set_path("/login");
            flash_cookie.set_max_age(time::Duration::seconds(5));

            (jar.add(flash_cookie), Redirect::to("/login"))
        }
    }
}

#[axum::debug_handler]
pub async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<RegisterRequest>,
) -> impl IntoResponse {
    let auth_service = AuthService::new(&state.db, &state.jwt_secret);

    match auth_service.register_user(&form.name, &form.email, &form.password, &form.plan).await {
        Ok(_) => {
            tracing::info!("✅ Registration successful");

            let mut flash_cookie = Cookie::new("flash", "Registration failed");
            flash_cookie.set_path("/register");
            flash_cookie.set_max_age(time::Duration::seconds(5));
            jar.add(flash_cookie).into_response();
        }
        Err(err) => {
            tracing::warn!("❌ Registration failed: {:?}", err);

            let mut flash_cookie = Cookie::new("flash", "Registration failed");
            flash_cookie.set_path("/register");
            flash_cookie.set_max_age(time::Duration::seconds(5));
            jar.add(flash_cookie).into_response();
        }
    }


}