use axum::{
    extract::State,
    response::IntoResponse,
    Json,
    http::StatusCode,
};
use serde::Deserialize;
use crate::services::auth_service::AuthService;
use crate::AppState;

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

#[derive(serde::Serialize)]
pub struct LoginResponse {
    pub token: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let auth_service = AuthService::new(&state.db, &state.jwt_secret);

    match auth_service.register_user(&payload.name, &payload.email, &payload.password).await {
        Ok(token) => {
            (StatusCode::OK, Json(LoginResponse { token })).into_response()
        }
        Err(err) => {
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": err }))).into_response()
        }
    }
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let auth_service = AuthService::new(&state.db, &state.jwt_secret);

    match auth_service.login_user(&payload.email, &payload.password).await {
        Ok(token) => {
            (StatusCode::OK, Json(LoginResponse { token })).into_response()
        }
        Err(_) => {
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid credentials"}))).into_response()
        }
    }
}
