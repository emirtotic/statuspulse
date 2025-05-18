use axum::{
    extract::{Path, State},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use serde::Deserialize;
use crate::{AppState, db::user_repository::UserRepository};

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
    // ✅ Provera da li korisnik ima auth_token
    let token = match jar.get("auth_token") {
        Some(cookie) => cookie.value().to_string(),
        None => {
            tracing::warn!("User not authenticated. Redirecting to register.");
            return Redirect::to("/register").into_response();
        }
    };

    // ✅ Provera da li je token validan
    let Some(user_id) = crate::utils::jwt_auth::decode_token(&token, &state.jwt_secret).ok() else {
        tracing::warn!("Invalid JWT token. Redirecting to login.");
        return Redirect::to("/login").into_response();
    };

    // ✅ Uzimamo trenutni plan korisnika
    let user_repo = UserRepository::new(&state.db);
    let current_plan = match user_repo.get_user_plan(user_id).await {
        Ok(Some(plan)) => plan,
        _ => "free".to_string(), // fallback ako ne uspe
    };

    // ✅ Mapiranje prioriteta planova
    let plan_priority = |p: &str| match p {
        "free" => 0,
        "pro" => 1,
        "enterprise" => 2,
        _ => -1,
    };

    // ✅ Ne dozvoli downgrade ili istu kupovinu
    if plan_priority(&plan) <= plan_priority(&current_plan) {
        tracing::warn!(
            "User {} has '{}' plan. Cannot downgrade to '{}'",
            user_id,
            current_plan,
            plan
        );
        let mut flash = Cookie::new("flash", "You already have this or a higher plan.");
        flash.set_path("/");
        flash.set_max_age(time::Duration::seconds(5));
        return (
            jar.add(flash),
            Redirect::to("/#pricing")
        ).into_response();
    }

    // ✅ Checkout URL za pro ili enterprise
    let base_url = match plan.as_str() {
        "pro" => &state.lemon_pro_url,
        "enterprise" => &state.lemon_enterprise_url,
        _ => {
            tracing::warn!("Unknown plan requested: '{}'", plan);
            return Redirect::to("/").into_response();
        }
    };

    // ✅ Dodavanje custom user_id u query string
    let redirect_url = format!(
        "{}?checkout[custom][user_id]={}",
        base_url,
        user_id
    );

    tracing::info!("Redirecting user {} to Lemon Squeezy → {}", user_id, redirect_url);
    Redirect::to(&redirect_url).into_response()
}
