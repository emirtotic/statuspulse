use axum::{extract::{Path, State}, response::{IntoResponse, Redirect}};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use crate::AppState;

#[derive(Deserialize)]
pub struct CheckoutPath {
    plan: String,
}

#[axum::debug_handler]
pub async fn checkout_handler(
    State(state): State<AppState>,
    Path(CheckoutPath { plan }): Path<CheckoutPath>,
    jar: CookieJar,
) -> impl IntoResponse {
    // Provera da li korisnik ima token
    let token = jar.get("auth_token").map(|c| c.value().to_string());
    let user_id = token.as_ref()
        .and_then(|t| crate::utils::jwt_auth::decode_token(t, &state.jwt_secret).ok());

    if user_id.is_none() {
        tracing::warn!("❌ User not authenticated. Redirecting to register.");
        return Redirect::to("/register").into_response();
    }

    // Odabir checkout URL-a
    let checkout_url = match plan.as_str() {
        "pro" => &state.lemon_pro_url,
        "enterprise" => &state.lemon_enterprise_url,
        _ => {
            tracing::warn!("❌ Unknown plan: {}. Redirecting to /", plan);
            return Redirect::to("/").into_response();
        }
    };

    tracing::info!("✅ Redirecting to Lemon Squeezy: {}", checkout_url);
    Redirect::to(checkout_url).into_response()
}
