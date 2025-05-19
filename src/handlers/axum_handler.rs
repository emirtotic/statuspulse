use axum::{response::Html, Extension, Form};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use tera::Tera;

use crate::db::user_repository::UserRepository;
use crate::models::monitor::{EditMonitorForm, MonitorStatusSummary};
use crate::utils::jwt_auth;
use crate::{db::monitor_repository::MonitorRepository, utils::jwt_auth::CurrentUser, AppState};
use axum::extract::Path;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::{extract::State, response::Redirect};
use http::{header, HeaderValue, StatusCode};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct CreateMonitorForm {
    pub label: String,
    pub url: String,
    pub interval_mins: i32,
}

// index (home) page
#[axum::debug_handler]
pub async fn landing_page(
    Extension(tera): Extension<Tera>,
    State(state): State<AppState>,
    jar: CookieJar,
) -> Html<String> {
    let mut ctx = tera::Context::new();

    if let Some(cookie) = jar.get("auth_token") {
        let token = cookie.value();
        match jwt_auth::decode_token(token, &state.jwt_secret) {
            Ok(user_id) => {
                ctx.insert("current_user", &user_id);
            }
            Err(_) => {
                ctx.remove("current_user");
            }
        }
    } else {
        ctx.remove("current_user");
    }

    let rendered = tera.render("index.html", &ctx).unwrap();
    Html(rendered)
}

#[axum::debug_handler]
pub async fn form_login(Extension(tera): Extension<Tera>, jar: CookieJar) -> Html<String> {
    let mut ctx = tera::Context::new();

    if let Some(cookie) = jar.get("flash") {
        ctx.insert("flash", cookie.value());
    }

    let rendered = tera.render("login.html", &ctx).unwrap();
    Html(rendered)
}

#[axum::debug_handler]
pub async fn form_register(Extension(tera): Extension<Tera>, jar: CookieJar) -> Html<String> {
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
    let user_repo = UserRepository::new(&state.db);

    let user = match user_repo.get_user_by_id(user_id).await {
        Ok(Some(user)) => user,
        _ => return Redirect::to("/login").into_response(),
    };

    let monitors = match monitor_repo.get_all_by_user(user_id).await {
        Ok(monitors) => monitors,
        Err(_) => Vec::new(),
    };

    // Priprema podataka za šablon
    let mut monitors_for_template = Vec::new();

    for monitor in &monitors {
        let last_status = status_log_repo
            .get_last_status_log(monitor.id)
            .await
            .ok()
            .flatten();

        monitors_for_template.push(serde_json::json!({
            "id": monitor.id,
            "label": monitor.label,
            "url": monitor.url,
            "is_active": monitor.is_active,
            "interval_mins": monitor.interval_mins,
            "is_up": monitor.is_up,
            "last_status": last_status,
        }));
    }

    // Kontekst za Tera
    let mut ctx = tera::Context::new();
    ctx.insert("monitors", &monitors_for_template);
    ctx.insert("current_user", &user_id);
    ctx.insert("user_name", &user.name);
    ctx.insert("user_plan", &user.plan);
    ctx.insert("on_dashboard", &true);

    let rendered = tera.render("dashboard.html", &ctx).unwrap();
    html_no_cache(Html(rendered))
}

#[axum::debug_handler]
pub async fn logout(jar: CookieJar) -> impl IntoResponse {
    let mut auth_cookie = Cookie::named("auth_token");
    auth_cookie.set_path("/");
    auth_cookie.set_http_only(true);
    auth_cookie.make_removal();

    use time::OffsetDateTime;
    auth_cookie.set_expires(OffsetDateTime::UNIX_EPOCH);

    let mut flash_cookie = Cookie::new("flash", "You have been logged out.");
    flash_cookie.set_path("/login");
    flash_cookie.set_max_age(time::Duration::seconds(5));

    (jar.add(auth_cookie).add(flash_cookie), Redirect::to("/"))
}

// Create on UI
#[axum::debug_handler]
pub async fn form_create_monitor(
    State(state): State<AppState>,
    Extension(tera): Extension<Tera>,
    jar: CookieJar,
) -> impl IntoResponse {

    let token = match jar.get("auth_token") {
        Some(cookie) => cookie.value().to_string(),
        None => return Redirect::to("/login").into_response(),
    };

    let user_id = match jwt_auth::decode_token(&token, &state.jwt_secret) {
        Ok(id) => id,
        Err(_) => return Redirect::to("/login").into_response(),
    };

    let user_repo = UserRepository::new(&state.db);
    let monitor_repo = MonitorRepository::new(&state.db);

    let user = match user_repo.get_user_by_id(user_id).await {
        Ok(Some(user)) => user,
        _ => return Redirect::to("/login").into_response(),
    };

    let monitor_count = monitor_repo
        .count_user_monitors(user_id)
        .await
        .unwrap_or(0);

    let min_interval_mins = match user.plan.as_str() {
        "free" => 15,
        "pro" => 5,
        "enterprise" => 1,
        _ => 15, // fallback
    };

    let mut ctx = tera::Context::new();
    ctx.insert("current_user", &user_id);
    ctx.insert("user_plan", &user.plan);
    ctx.insert("monitor_count", &monitor_count);
    ctx.insert("min_interval_mins", &min_interval_mins);

    match tera.render("create_monitor.html", &ctx) {
        Ok(rendered) => html_no_cache(Html(rendered)),
        Err(err) => {
            tracing::error!("Template error: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Template rendering failed".to_string(),
            )
                .into_response()
        }
    }
}

// Update on UI
#[axum::debug_handler]
pub async fn form_edit_monitor(
    State(state): State<AppState>,
    Extension(tera): Extension<Tera>,
    Path(monitor_id): Path<u64>,
    jar: CookieJar,
) -> impl IntoResponse {

    let token = match jar.get("auth_token") {
        Some(cookie) => cookie.value().to_string(),
        None => return Redirect::to("/login").into_response(),
    };

    let user_id = match jwt_auth::decode_token(&token, &state.jwt_secret) {
        Ok(id) => id,
        Err(_) => return Redirect::to("/login").into_response(),
    };

    let user_repo = UserRepository::new(&state.db);
    let monitor_repo = MonitorRepository::new(&state.db);

    let monitor = match monitor_repo.get_monitor_by_id(monitor_id, user_id).await {
        Ok(Some(m)) => m,
        _ => return Redirect::to("/dashboard").into_response(),
    };

    let user = match user_repo.get_user_by_id(user_id).await {
        Ok(Some(u)) => u,
        _ => return Redirect::to("/login").into_response(),
    };

    let min_interval_mins = match user.plan.as_str() {
        "free" => 15,
        "pro" => 5,
        "enterprise" => 1,
        _ => 15,
    };

    let mut ctx = tera::Context::new();
    ctx.insert("monitor", &monitor);
    ctx.insert("current_user", &user_id);
    ctx.insert("user_plan", &user.plan);
    ctx.insert("min_interval_mins", &min_interval_mins);

    match tera.render("edit_monitor.html", &ctx) {
        Ok(rendered) => html_no_cache(Html(rendered)),
        Err(err) => {
            tracing::error!("Template error: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Template rendering failed".to_string(),
            )
                .into_response()
        }
    }
}


#[axum::debug_handler]
pub async fn delete_monitor_form(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(monitor_id): Path<u64>,
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

    let repo = MonitorRepository::new(&state.db);

    match repo.delete_monitor(monitor_id, user_id).await {
        Ok(affected) if affected > 0 => {
            tracing::info!("Monitor {} deleted by user {}", monitor_id, user_id);
        }
        Ok(_) => {
            tracing::warn!(
                "Monitor {} not found or unauthorized for user {}",
                monitor_id,
                user_id
            );
        }
        Err(e) => {
            tracing::error!("Failed to delete monitor {}: {:?}", monitor_id, e);
        }
    }

    Redirect::to("/dashboard").into_response()
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

    let user_repo = UserRepository::new(&state.db);
    let monitor_repo = MonitorRepository::new(&state.db);

    // Fetch user plan
    let user_plan = match user_repo.get_user_plan(user_id).await {
        Ok(Some(plan)) => plan,
        Ok(None) => {
            tracing::warn!("User plan not found for user_id: {}", user_id);
            let mut flash_cookie = Cookie::new("flash", "User plan not found.");
            flash_cookie.set_path("/monitors/new");
            flash_cookie.set_max_age(time::Duration::seconds(5));
            return (jar.add(flash_cookie), Redirect::to("/monitors/new")).into_response();
        }
        Err(_) => {
            tracing::error!("Failed to fetch user plan for user_id: {}", user_id);
            let mut flash_cookie = Cookie::new("flash", "Internal error fetching user plan.");
            flash_cookie.set_path("/monitors/new");
            flash_cookie.set_max_age(time::Duration::seconds(5));
            return (jar.add(flash_cookie), Redirect::to("/monitors/new")).into_response();
        }
    };

    // Count existing monitors
    let monitor_count = match monitor_repo.count_user_monitors(user_id).await {
        Ok(count) => count,
        Err(_) => {
            tracing::error!("Failed to count monitors for user_id: {}", user_id);
            let mut flash_cookie = Cookie::new("flash", "Internal error counting monitors.");
            flash_cookie.set_path("/monitors/new");
            flash_cookie.set_max_age(time::Duration::seconds(5));
            return (jar.add(flash_cookie), Redirect::to("/monitors/new")).into_response();
        }
    };

    // Check if user can create more monitors based on plan
    let allowed = match user_plan.as_str() {
        "free" => monitor_count < 2,
        "pro" => monitor_count < 15,
        "enterprise" => true,
        _ => false,
    };

    if !allowed {
        tracing::error!(
            "User {} reached monitor limit for plan '{}'",
            user_id,
            user_plan
        );
        let mut flash_cookie = Cookie::new("flash", "Monitor limit reached for your plan.");
        flash_cookie.set_path("/monitors/new");
        flash_cookie.set_max_age(time::Duration::seconds(5));
        return (jar.add(flash_cookie), Redirect::to("/monitors/new")).into_response();
    }

    // Create monitor
    match monitor_repo
        .create_monitor(user_id, &form.label, &form.url, form.interval_mins)
        .await
    {
        Ok(_) => Redirect::to("/dashboard").into_response(),
        Err(e) => {
            tracing::error!("Failed to create monitor: {:?}", e);
            let mut flash_cookie = Cookie::new("flash", "Failed to create monitor.");
            flash_cookie.set_path("/monitors/new");
            flash_cookie.set_max_age(time::Duration::seconds(5));
            (jar.add(flash_cookie), Redirect::to("/monitors/new")).into_response()
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

    match repo
        .update_monitor(
            monitor_id,
            user_id,
            &form.label,
            &form.url,
            form.interval_mins,
            is_active,
        )
        .await
    {
        Ok(affected) if affected > 0 => {
            tracing::info!("Monitor {} updated by user {}", monitor_id, user_id);

            let mut flash_cookie = Cookie::new("flash", "Monitor updated successfully.");
            flash_cookie.set_path("/dashboard");
            flash_cookie.set_max_age(time::Duration::seconds(5));

            return (jar.add(flash_cookie), Redirect::to("/dashboard")).into_response();
        }
        Ok(_) => {
            tracing::warn!(
                "Monitor {} not found or unauthorized for user {}",
                monitor_id,
                user_id
            );
        }
        Err(e) => {
            tracing::error!("Failed to update monitor {}: {:?}", monitor_id, e);
        }
    }

    Redirect::to("/dashboard").into_response()
}

#[axum::debug_handler]
pub async fn error_page(Extension(tera): Extension<Tera>) -> impl IntoResponse {
    let rendered = tera
        .render("error.html", &tera::Context::new())
        .unwrap_or_else(|_| "<h1>Error</h1><p>Something went wrong.</p>".to_string());

    (StatusCode::NOT_FOUND, Html(rendered))
}

#[axum::debug_handler]
pub async fn internal_error_page(Extension(tera): Extension<Tera>) -> impl IntoResponse {
    let rendered = tera
        .render("error_500.html", &tera::Context::new())
        .unwrap_or_else(|_| "<h1>500 Internal Server Error</h1><p>We're sorry!</p>".to_string());

    (StatusCode::INTERNAL_SERVER_ERROR, Html(rendered))
}

fn html_no_cache(body: Html<String>) -> Response {
    let mut res = body.into_response();
    let headers = res.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
    res
}
