pub mod monitor_routes;

use crate::{handlers::auth_handler, AppState};
use axum::response::IntoResponse;
use axum::{routing::post, Router};

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(auth_handler::login))
        .route("/register", post(auth_handler::register))
}

