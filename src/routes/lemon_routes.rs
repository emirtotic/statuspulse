use axum::{Router, routing::post};
use crate::{AppState, handlers::lemon_webhook_handler};

pub fn lemon_routes() -> Router<AppState> {
    Router::new()
        .route("/lemon", post(lemon_webhook_handler::lemon_webhook))
}
