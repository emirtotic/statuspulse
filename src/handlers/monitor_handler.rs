use axum::{extract::State, response::IntoResponse, Json};
use crate::{AppState, utils::jwt_auth::CurrentUser};

pub async fn list_monitors(
    State(_state): State<AppState>,
    current_user: CurrentUser,
) -> impl IntoResponse {
    let msg = format!("Listing monitors for user_id: {}", current_user.user_id);
    Json(serde_json::json!({ "message": msg }))
}
