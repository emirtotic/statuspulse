use axum::{Router, routing::get};
use crate::{handlers::monitor_handler, AppState};

pub fn monitor_routes() -> Router<AppState> {
    Router::new()
        .route("/monitors", get(monitor_handler::list_monitors))
}
