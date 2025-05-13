use axum::{Router, routing::{get, post, delete, put}};
use crate::{handlers::monitor_handler, handlers::status_log_handler, AppState};

pub fn monitor_routes() -> Router<AppState> {
    Router::new()
        .route("/monitors", get(monitor_handler::list_monitors))
        .route("/monitors/inactive", get(monitor_handler::list_inactive_monitors))
        .route("/monitors/active", get(monitor_handler::list_active_monitors))
        .route("/monitors", post(monitor_handler::create_monitor))
        .route("/monitors/:id", delete(monitor_handler::delete_monitor))
        .route("/monitors/:id", put(monitor_handler::update_monitor))

        .route("/monitors/:id/logs", get(status_log_handler::list_status_logs))
        .route("/monitors/:id/status", get(monitor_handler::get_monitor_status))
}
