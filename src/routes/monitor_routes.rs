use axum::{Router, routing::{get, post, delete, put}};
use crate::{handlers::monitor_handler, AppState};

pub fn monitor_routes() -> Router<AppState> {
    Router::new()
        .route("/monitors", get(monitor_handler::list_monitors))
        .route("/monitors", post(monitor_handler::create_monitor))
        .route("/monitors/:id", delete(monitor_handler::delete_monitor))
        .route("/monitors/:id", put(monitor_handler::update_monitor))
}
