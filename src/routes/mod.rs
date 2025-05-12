pub mod monitor_routes;

use axum::{Router, routing::post, Json};
use axum::extract::State;
use axum::response::IntoResponse;
use crate::{handlers::auth_handler, AppState};
use crate::utils::jwt_auth::CurrentUser;

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(auth_handler::login))
}
