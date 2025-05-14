use axum::{extract::{State, Form}, response::IntoResponse, response::Redirect};
use serde::{Deserialize, Serialize};
use crate::{services::auth_service::AuthService, AppState};
use axum_extra::extract::cookie::{Cookie, CookieJar};

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    pub email: String,
    pub password: String,
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
        Ok(_token) => {
            Redirect::to("/dashboard").into_response()
        }
        Err(_) => {
            let jar = jar.add(Cookie::build("flash").path("/").build());
            (jar, Redirect::to("/login")).into_response()
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

    match auth_service.register_user(&form.name, &form.email, &form.password).await {
        Ok(_token) => {
            let jar = jar.add(Cookie::build("flash").path("/").build());
            (jar, Redirect::to("/login")).into_response()
        }
        Err(_err_msg) => {
            let jar = jar.add(Cookie::build("flash").path("/").build());
            (jar, Redirect::to("/register")).into_response()
        }
    }
}
