use axum::{
    extract::{State, Path, Query},
    response::IntoResponse,
    Json,
    http::StatusCode,
};
use crate::{
    AppState,
    db::{status_log_repository::StatusLogRepository, user_repository::UserRepository, monitor_repository::MonitorRepository},
    utils::jwt_auth::CurrentUser,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct LogQuery {
    pub limit: Option<u32>,
}

pub async fn list_status_logs(
    State(state): State<AppState>,
    CurrentUser { user_id }: CurrentUser,
    Path(monitor_id): Path<u64>,
    Query(query): Query<LogQuery>,
) -> impl IntoResponse {
    let user_repo = UserRepository::new(&state.db);

    // Check does user exist
    if !user_repo.exists_by_id(user_id).await.unwrap_or(false) {
        tracing::warn!("Unauthorized access attempt by non-existing user_id: {}", user_id);
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "User not found"}))).into_response();
    }

    // Check does the monitor belong to the user
    let monitor_repo = MonitorRepository::new(&state.db);

    match monitor_repo.get_monitor_by_id(monitor_id, user_id).await {
        Ok(Some(_)) => {
            // User is the log owner
        },
        Ok(None) => {
            tracing::warn!("User_id {} tried to access monitor_id {} which is not theirs", user_id, monitor_id);
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Forbidden"}))).into_response();
        },
        Err(e) => {
            tracing::error!("Failed to verify monitor ownership: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Internal server error"}))).into_response();
        }
    }

    // Fetch status logs
    let repo = StatusLogRepository::new(&state.db);
    let limit = query.limit.unwrap_or(50);

    match repo.get_logs_by_monitor(monitor_id, limit).await {
        Ok(logs) => (StatusCode::OK, Json(logs)).into_response(),
        Err(e) => {
            tracing::error!("Failed to fetch status logs for monitor_id {}: {:?}", monitor_id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to fetch logs"}))).into_response()
        }
    }
}
