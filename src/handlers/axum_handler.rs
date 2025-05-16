use axum::{Extension, response::Html, Form};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use tera::Tera;

use axum::{
    extract::{State},
    response::{Redirect},
};
use axum::extract::Path;
use axum::response::IntoResponse;
use serde::Deserialize;
use crate::{AppState, db::monitor_repository::MonitorRepository, utils::jwt_auth::CurrentUser};
use crate::models::monitor::{EditMonitorForm, MonitorStatusSummary};


// index (home) page
#[axum::debug_handler]
pub async fn landing_page(
    Extension(tera): Extension<Tera>,
) -> Html<String> {
    let ctx = tera::Context::new();
    let rendered = tera.render("index.html", &ctx).unwrap();
    Html(rendered)
}


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

#[axum::debug_handler]
pub async fn logout(
    jar: CookieJar,
) -> impl IntoResponse {
    // Remove auth_token cookie
    let mut auth_cookie = Cookie::named("auth_token");
    auth_cookie.set_path("/");
    auth_cookie.make_removal();

    // Flash logout message
    let mut flash_cookie = Cookie::new("flash", "You have been logged out.");
    flash_cookie.set_path("/login");
    flash_cookie.set_max_age(time::Duration::seconds(5));

    (
        jar.add(auth_cookie).add(flash_cookie),
        Redirect::to("/login")
    )
}

#[axum::debug_handler]
pub async fn form_create_monitor(
    Extension(tera): Extension<Tera>,
) -> impl IntoResponse {
    let ctx = tera::Context::new();
    let rendered = tera.render("create_monitor.html", &ctx).unwrap();
    Html(rendered).into_response()
}

#[axum::debug_handler]
pub async fn form_edit_monitor(
    State(state): State<AppState>,
    Extension(tera): Extension<Tera>,
    Path(monitor_id): Path<u64>,
    jar: CookieJar,
) -> impl IntoResponse {
    let token = jar.get("auth_token").map(|c| c.value().to_string());
    let user_id = match token
        .as_ref()
        .and_then(|t| crate::utils::jwt_auth::decode_token(t, &state.jwt_secret).ok())
    {
        Some(id) => id,
        None => return Redirect::to("/login").into_response(),
    };

    let monitor_repo = MonitorRepository::new(&state.db);
    let monitor = match monitor_repo.get_monitor_by_id(monitor_id, user_id).await {
        Ok(Some(m)) => m,
        _ => return Redirect::to("/dashboard").into_response(),
    };

    let mut ctx = tera::Context::new();
    ctx.insert("monitor", &monitor);

    let rendered = tera.render("edit_monitor.html", &ctx).unwrap();
    Html(rendered).into_response()
}

#[axum::debug_handler]
pub async fn delete_monitor_form(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(monitor_id): Path<u64>,
) -> impl IntoResponse {
    // Autentifikacija preko cookie
    let token = if let Some(cookie) = jar.get("auth_token") {
        cookie.value().to_string()
    } else {
        return Redirect::to("/login").into_response();
    };

    // Decode token i uzmi user_id
    let user_id = match crate::utils::jwt_auth::decode_token(&token, &state.jwt_secret) {
        Ok(id) => id,
        Err(_) => return Redirect::to("/login").into_response(),
    };

    let repo = MonitorRepository::new(&state.db);

    // Pokušaj brisanja monitora
    match repo.delete_monitor(monitor_id, user_id).await {
        Ok(affected) if affected > 0 => {
            tracing::info!("Monitor {} deleted by user {}", monitor_id, user_id);
        }
        Ok(_) => {
            tracing::warn!("Monitor {} not found or unauthorized for user {}", monitor_id, user_id);
        }
        Err(e) => {
            tracing::error!("Failed to delete monitor {}: {:?}", monitor_id, e);
        }
    }

    Redirect::to("/dashboard").into_response()
}

#[derive(Deserialize)]
pub struct CreateMonitorForm {
    pub label: String,
    pub url: String,
    pub interval_mins: i32,
}

#[axum::debug_handler]
pub async fn create_monitor_form(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<CreateMonitorForm>,
) -> impl IntoResponse {
    // Auth via cookie
    let token = if let Some(cookie) = jar.get("auth_token") {
        cookie.value().to_string()
    } else {
        return Redirect::to("/login").into_response();
    };

    // Decode token -> user_id
    let user_id = match crate::utils::jwt_auth::decode_token(&token, &state.jwt_secret) {
        Ok(id) => id,
        Err(_) => return Redirect::to("/login").into_response(),
    };

    let repo = MonitorRepository::new(&state.db);

    // Try create monitor
    match repo.create_monitor(user_id, &form.label, &form.url, form.interval_mins).await {
        Ok(_) => Redirect::to("/dashboard").into_response(),
        Err(e) => {
            tracing::error!("Failed to create monitor: {:?}", e);

            // Flash error message
            let mut flash_cookie = Cookie::new("flash", "Failed to create monitor.");
            flash_cookie.set_path("/monitors/new");
            flash_cookie.set_max_age(time::Duration::seconds(5));

            (
                jar.add(flash_cookie),
                Redirect::to("/monitors/new")
            ).into_response()
        }
    }
}

#[axum::debug_handler]
pub async fn edit_monitor_form(
    State(state): State<AppState>,
    Path(monitor_id): Path<u64>,
    jar: CookieJar,
    Form(form): Form<EditMonitorForm>,
) -> impl IntoResponse {
    let token = jar.get("auth_token").map(|c| c.value().to_string());
    let user_id = match token
        .as_ref()
        .and_then(|t| crate::utils::jwt_auth::decode_token(t, &state.jwt_secret).ok())
    {
        Some(id) => id,
        None => return Redirect::to("/login").into_response(),
    };

    // Ovo je sada prava logika: match stringa
    let is_active = form.is_active == Some("true".to_string());

    let repo = MonitorRepository::new(&state.db);

    match repo.update_monitor(
        monitor_id,
        user_id,
        &form.label,
        &form.url,
        form.interval_mins,
        is_active,
    ).await {
        Ok(affected) if affected > 0 => {
            tracing::info!("Monitor {} updated by user {}", monitor_id, user_id);

            let mut flash_cookie = Cookie::new("flash", "Monitor updated successfully.");
            flash_cookie.set_path("/dashboard");
            flash_cookie.set_max_age(time::Duration::seconds(5));

            return (
                jar.add(flash_cookie),
                Redirect::to("/dashboard")
            ).into_response();
        }
        Ok(_) => {
            tracing::warn!("Monitor {} not found or unauthorized for user {}", monitor_id, user_id);
        }
        Err(e) => {
            tracing::error!("Failed to update monitor {}: {:?}", monitor_id, e);
        }
    }

    Redirect::to("/dashboard").into_response()
}
