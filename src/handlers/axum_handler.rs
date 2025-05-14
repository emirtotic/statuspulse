use axum::{Extension, response::Html};
use axum_extra::extract::cookie::CookieJar;
use tera::Tera;

use axum::{
    extract::{State},
    response::{Redirect},
};
use axum::response::IntoResponse;
use crate::{AppState, db::monitor_repository::MonitorRepository, utils::jwt_auth::CurrentUser};
use crate::models::monitor::MonitorStatusSummary;

#[axum::debug_handler]
pub async fn form_login(
    Extension(tera): Extension<Tera>,
    jar: CookieJar,
) -> Html<String> {
    let mut ctx = tera::Context::new();

    if let Some(cookie) = jar.get("flash") {
        ctx.insert("flash", cookie.value());
    }

    let rendered = tera.render("login.html", &ctx).unwrap();
    Html(rendered)
}

#[axum::debug_handler]
pub async fn form_register(
    Extension(tera): Extension<Tera>,
    jar: CookieJar,
) -> Html<String> {
    let mut ctx = tera::Context::new();

    if let Some(cookie) = jar.get("flash") {
        ctx.insert("flash", cookie.value());
    }

    let rendered = tera.render("register.html", &ctx).unwrap();
    Html(rendered)
}

#[axum::debug_handler]
pub async fn dashboard(
    State(state): State<AppState>,
    Extension(tera): Extension<Tera>,
    jar: CookieJar,
) -> impl IntoResponse {
    let token = if let Some(cookie) = jar.get("auth_token") {
        cookie.value().to_string()
    } else {
        return Redirect::to("/login").into_response();
    };

    let user_id = match crate::utils::jwt_auth::decode_token(&token, &state.jwt_secret) {
        Ok(id) => id,
        Err(_) => return Redirect::to("/login").into_response(),
    };

    let monitor_repo = MonitorRepository::new(&state.db);
    let status_log_repo = crate::db::status_log_repository::StatusLogRepository::new(&state.db);

    let monitors = match monitor_repo.get_all_by_user(user_id).await {
        Ok(monitors) => monitors,
        Err(_) => Vec::new(),
    };

    let mut dashboard_data = Vec::new();

    // Iteriraj monitors po referenci (&) da ih ne premestiš ownership-om
    for monitor in &monitors {
        let last_status = status_log_repo.get_last_status_log(monitor.id).await.ok().flatten();
        let uptime_percentage = status_log_repo.get_uptime_percentage(monitor.id).await.unwrap_or(0.0);
        let avg_response_time = status_log_repo.get_avg_response_time(monitor.id).await.unwrap_or(None);

        dashboard_data.push(MonitorStatusSummary {
            monitor_id: monitor.id,
            last_status,
            uptime_percentage,
            average_response_time_ms: avg_response_time,
        });
    }

    // Ovo ostaje isto (jer monitors još uvek živi)
    let monitors_for_template = dashboard_data.into_iter().map(|summary| {
        let monitor = monitors.iter().find(|m| m.id == summary.monitor_id).unwrap();

        serde_json::json!({
        "id": monitor.id,
        "label": monitor.label,
        "url": monitor.url,
        "is_active": monitor.is_active,
        "interval_mins": monitor.interval_mins,
        "uptime_percentage": summary.uptime_percentage,
    })
    }).collect::<Vec<_>>();


    let mut ctx = tera::Context::new();
    ctx.insert("monitors", &monitors_for_template);

    let rendered = tera.render("dashboard.html", &ctx).unwrap();
    Html(rendered).into_response()
}





