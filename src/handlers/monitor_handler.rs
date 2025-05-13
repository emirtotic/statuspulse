use axum::{
    extract::{State, Path},
    response::IntoResponse,
    Json,
    http::StatusCode,
};
use crate::{
    AppState,
    utils::jwt_auth::CurrentUser,
    db::monitor_repository::MonitorRepository,
    models::monitor::Monitor,
};
use serde::Deserialize;
use crate::db::user_repository::UserRepository;

#[derive(Deserialize)]
pub struct CreateMonitorRequest {
    pub label: String,
    pub url: String,
    pub interval_mins: i32,
}

#[derive(Deserialize)]
pub struct UpdateMonitorRequest {
    pub label: Option<String>,
    pub url: Option<String>,
    pub interval_mins: Option<i32>,
    pub is_active: Option<bool>,
}

pub async fn list_monitors(
    State(state): State<AppState>,
    CurrentUser { user_id }: CurrentUser,
) -> impl IntoResponse {
    tracing::info!("Fetching monitors for user_id: {}", user_id);

    let user_repo = UserRepository::new(&state.db);

    if !user_repo.exists_by_id(user_id).await.unwrap_or(false) {
        tracing::warn!("Unauthorized access attempt by non-existing user_id: {}", user_id);
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "User not found"}))).into_response();
    }

    let repo = MonitorRepository::new(&state.db);

    match repo.get_all_by_user(user_id).await {
        Ok(monitors) => {
            tracing::info!("Found {} monitors for user_id {}", monitors.len(), user_id);
            (StatusCode::OK, Json(monitors)).into_response()
        },
        Err(e) => {
            tracing::error!("Failed to fetch monitors for user_id {}: {:?}", user_id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to fetch monitors"}))).into_response()
        }
    }
}

pub async fn create_monitor(
    State(state): State<AppState>,
    CurrentUser { user_id }: CurrentUser,
    Json(payload): Json<CreateMonitorRequest>,
) -> impl IntoResponse {

    let user_repo = UserRepository::new(&state.db);

    if !user_repo.exists_by_id(user_id).await.unwrap_or(false) {
        tracing::warn!("Unauthorized access attempt by non-existing user_id: {}", user_id);
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "User not found"}))).into_response();
    }

    let repo = MonitorRepository::new(&state.db);

    match repo.create_monitor(user_id, &payload.label, &payload.url, payload.interval_mins).await {
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({ "id": id }))).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to create monitor"}))).into_response(),
    }
}

pub async fn delete_monitor(
    State(state): State<AppState>,
    CurrentUser { user_id }: CurrentUser,
    Path(monitor_id): Path<u64>,
) -> impl IntoResponse {

    let user_repo = UserRepository::new(&state.db);

    if !user_repo.exists_by_id(user_id).await.unwrap_or(false) {
        tracing::warn!("Unauthorized access attempt by non-existing user_id: {}", user_id);
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "User not found"}))).into_response();
    }

    let repo = MonitorRepository::new(&state.db);

    match repo.delete_monitor(monitor_id, user_id).await {
        Ok(affected) if affected > 0 => (StatusCode::NO_CONTENT).into_response(),
        _ => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Monitor not found"}))).into_response(),
    }
}

pub async fn update_monitor(
    State(state): State<AppState>,
    CurrentUser { user_id }: CurrentUser,
    Path(monitor_id): Path<u64>,
    Json(payload): Json<UpdateMonitorRequest>,
) -> impl IntoResponse {

    let user_repo = UserRepository::new(&state.db);

    if !user_repo.exists_by_id(user_id).await.unwrap_or(false) {
        tracing::warn!("Unauthorized access attempt by non-existing user_id: {}", user_id);
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "User not found"}))).into_response();
    }

    let repo = MonitorRepository::new(&state.db);

    tracing::info!("Updating monitor_id {} for user_id {}", monitor_id, user_id);

    // Fetch existing monitor to handle Option<T> fields (partial update)
    let existing_monitor = match repo.get_monitor_by_id(monitor_id, user_id).await {
        Ok(Some(monitor)) => monitor,
        Ok(None) => {
            tracing::warn!("Monitor not found for id {} and user_id {}", monitor_id, user_id);
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Monitor not found"}))).into_response();
        }
        Err(e) => {
            tracing::error!("Failed to fetch monitor: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to fetch monitor"}))).into_response();
        }
    };

    let label = payload.label.as_deref().unwrap_or(&existing_monitor.label);
    let url = payload.url.as_deref().unwrap_or(&existing_monitor.url);
    let interval_mins = payload.interval_mins.unwrap_or(existing_monitor.interval_mins);
    let is_active = payload.is_active.unwrap_or(existing_monitor.is_active);

    match repo.update_monitor(monitor_id, user_id, label, url, interval_mins, is_active).await {
        Ok(affected) if affected > 0 => {
            (StatusCode::OK, Json(serde_json::json!({ "message": "Monitor updated" }))).into_response()
        },
        Ok(_) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Monitor not found" }))).into_response()
        },
        Err(e) => {
            tracing::error!("Failed to update monitor: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Failed to update monitor" }))).into_response()
        }
    }
}

pub async fn list_inactive_monitors(
    State(state): State<AppState>,
    CurrentUser { user_id }: CurrentUser,
) -> impl IntoResponse {
    tracing::info!("Fetching inactive monitors for user_id: {}", user_id);

    let user_repo = UserRepository::new(&state.db);

    if !user_repo.exists_by_id(user_id).await.unwrap_or(false) {
        tracing::warn!("Unauthorized access attempt by non-existing user_id: {}", user_id);
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "User not found"}))).into_response();
    }

    let repo = MonitorRepository::new(&state.db);

    match repo.get_all_inactive_monitors(user_id).await {
        Ok(monitors) => {
            tracing::info!("Found {} inactive monitors for user_id {}", monitors.len(), user_id);
            (StatusCode::OK, Json(monitors)).into_response()
        },
        Err(e) => {
            tracing::error!("Failed to fetch inactive monitors for user_id {}: {:?}", user_id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to fetch inactive monitors"}))).into_response()
        }
    }
}

pub async fn list_active_monitors(
    State(state): State<AppState>,
    CurrentUser { user_id }: CurrentUser,
) -> impl IntoResponse {
    tracing::info!("Fetching active monitors for user_id: {}", user_id);

    let user_repo = UserRepository::new(&state.db);

    if !user_repo.exists_by_id(user_id).await.unwrap_or(false) {
        tracing::warn!("Unauthorized access attempt by non-existing user_id: {}", user_id);
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "User not found"}))).into_response();
    }

    let repo = MonitorRepository::new(&state.db);

    match repo.get_all_active_monitors(user_id).await {
        Ok(monitors) => {
            tracing::info!("Found {} active monitors for user_id {}", monitors.len(), user_id);
            (StatusCode::OK, Json(monitors)).into_response()
        },
        Err(e) => {
            tracing::error!("Failed to fetch active monitors for user_id {}: {:?}", user_id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to fetch active monitors"}))).into_response()
        }
    }
}

