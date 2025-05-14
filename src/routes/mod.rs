use axum::{Router, routing::{get, post}};
use crate::{AppState, handlers::{auth_handler, axum_handler}};
pub mod monitor_routes;

pub fn api_auth_routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(auth_handler::login))
        .route("/register", post(auth_handler::register))
}

pub fn frontend_auth_routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(axum_handler::form_login).post(axum_handler::form_login))
        .route("/register", get(axum_handler::form_register).post(axum_handler::form_register))
}
