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

type HmacSha256 = Hmac<Sha256>;
const SIGNATURE_HEADER: &str = "X-Signature";

pub async fn lemon_webhook(
    State(_state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Signature secret
    let secret = env::var("LEMON_WEBHOOK_SECRET").unwrap_or_default();

    if let Some(sig_header) = headers.get(SIGNATURE_HEADER) {
        let sig_hex = sig_header.to_str().unwrap_or_default();
        let signature = match hex::decode(sig_hex) {
            Ok(sig) => sig,
            Err(_) => return StatusCode::UNAUTHORIZED,
        };

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(&body);

        if mac.verify_slice(&signature).is_err() {
            tracing::error!("Invalid signature");
            return StatusCode::UNAUTHORIZED;
        }
    } else {
        tracing::error!("Missing signature header");
        return StatusCode::UNAUTHORIZED;
    }

    let body_str = String::from_utf8(body.to_vec()).unwrap_or_default();
    tracing::info!("Webhook body: {}", body_str);

    let parsed: Value = match serde_json::from_str(&body_str) {
        Ok(val) => val,
        Err(err) => {
            tracing::error!("Failed to parse JSON: {:?}", err);
            return StatusCode::BAD_REQUEST;
        }
    };

    if let Some(event) = parsed.get("meta").and_then(|m| m.get("event_name")).and_then(|e| e.as_str()) {
        match event {
            "order_created" | "subscription_payment_success" => {
                if let Some(email) = parsed.get("data")
                    .and_then(|d| d.get("attributes"))
                    .and_then(|a| a.get("user_email"))
                    .and_then(|e| e.as_str()) {
                    tracing::info!("Order successful for: {}", email);
                    // TODO: updateuj plan u bazi ovde
                }
            }
            _ => {
                tracing::info!("Error occurred for event: {}", event);
            }
        }
    }

    StatusCode::OK
}
