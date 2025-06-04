use axum::{
    extract::{State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    body::Bytes,
};
use crate::AppState;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::env;
use serde_json::Value;
use tracing::info;
use crate::db::user_repository::UserRepository;

type HmacSha256 = Hmac<Sha256>;
const SIGNATURE_HEADER: &str = "X-Signature";

fn is_valid_signature(secret: &str, payload: &Bytes, signature: &str) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload);
    match hex::decode(signature) {
        Ok(sig_bytes) => mac.verify_slice(&sig_bytes).is_ok(),
        Err(_) => false,
    }
}

pub async fn lemon_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let secret = env::var("LEMON_WEBHOOK_SECRET").unwrap_or_default();

    let Some(sig_header) = headers.get(SIGNATURE_HEADER) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let sig_hex = sig_header.to_str().unwrap_or("");
    if !is_valid_signature(&secret, &body, sig_hex) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let event: Value = match serde_json::from_slice(&body) {
        Ok(json) => json,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let user_id = event["meta"]["custom_data"]["user_id"].as_str()
        .and_then(|s| s.parse::<u64>().ok());
    let plan = event["data"]["attributes"]["variant_name"].as_str().unwrap_or("free");

    if let Some(user_id) = user_id {
        let repo = UserRepository::new(&state.db);

        match repo.update_user_plan(user_id, plan).await {
            Ok(_) => info!("Updated user {} to plan {} via LemonSqueezy", user_id, plan),
            Err(e) => tracing::error!("Failed to update plan: {}", e),
        }
    }

    StatusCode::OK.into_response()
}

