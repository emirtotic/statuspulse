use axum::{response::Html, Extension, Form};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use tera::{Context, Tera};

use crate::db::user_repository::UserRepository;
use crate::models::monitor::{EditMonitorForm, MonitorStatusSummary};
use crate::utils::jwt_auth;
use crate::{db::monitor_repository::MonitorRepository, utils::jwt_auth::CurrentUser, AppState};
use axum::extract::Path;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::{extract::State, response::Redirect};
use http::{header, HeaderValue, StatusCode};
use serde::{Deserialize};
use time::format_description::parse;
use crate::services::sendgrid_service::SendGridService;

#[derive(Deserialize)]
pub struct CreateMonitorForm {
    pub label: String,
    pub url: String,
    pub interval_mins: i32,
}

#[derive(Deserialize)]
pub struct ContactForm {
    pub name: String,
    pub email: String,
    pub message: String,
    pub website: Option<String>, // honeypot
    #[serde(rename = "g-recaptcha-response")]
    pub recaptcha_token: String,
}

// index (home) page
#[axum::debug_handler]
pub async fn landing_page(
    Extension(tera): Extension<Tera>,
    State(state): State<AppState>,
    jar: CookieJar,
) -> Html<String> {
    let contact_email = std::env::var("CONTACT_EMAIL").unwrap_or("contact@example.com".into());
    let mut ctx = tera::Context::new();
    ctx.insert("contact_email", &contact_email);
    ctx.insert("RECAPTCHA_SITE_KEY", &std::env::var("RECAPTCHA_SITE_KEY").unwrap_or_default());

    if let Some(cookie) = jar.get("flash") {
        ctx.insert("flash", cookie.value());
    }

    let user_repo = UserRepository::new(&state.db);
    if let Some(cookie) = jar.get("auth_token") {
        let token = cookie.value();
        match jwt_auth::decode_token(token, &state.jwt_secret) {
            Ok(user_id) => {
                ctx.insert("current_user", &user_id);
                match user_repo.get_user_by_id(user_id).await {
                    Ok(Some(user)) => {
                        ctx.insert("user_plan", &user.plan);
                        ctx.insert("user_name", &user.name);
                        ctx.insert("user_email", &user.email);
                    }
                    _ => {
                        ctx.insert("user_plan", "free");
                    }
                }
            }
            Err(_) => {
                ctx.insert("user_plan", "guest");
            }
        }
    } else {
        ctx.insert("user_plan", "guest");
    }

    let rendered = tera.render("index.html", &ctx).unwrap_or_else(|e| {
        tracing::error!("Template rendering failed: {:?}", e);
        "Internal Server Error".to_string()
    });

    Html(rendered)
}

#[axum::debug_handler]
pub async fn form_login(Extension(tera): Extension<Tera>, jar: CookieJar) -> Html<String> {
    let mut ctx = tera::Context::new();
    ctx.insert("RECAPTCHA_SITE_KEY", &std::env::var("RECAPTCHA_SITE_KEY").unwrap_or_default());

    if let Some(cookie) = jar.get("flash") {
        ctx.insert("flash", cookie.value());
    }

    let rendered = tera.render("login.html", &ctx).unwrap();
    Html(rendered)
}

#[axum::debug_handler]
pub async fn form_register(Extension(tera): Extension<Tera>, jar: CookieJar) -> Html<String> {
    let mut ctx = tera::Context::new();
    ctx.insert("RECAPTCHA_SITE_KEY", &std::env::var("RECAPTCHA_SITE_KEY").unwrap_or_default());
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

#[axum::debug_handler]
pub async fn submit_contact_form(
    State(_state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<ContactForm>,
) -> impl IntoResponse {
    let sendgrid = SendGridService::new(
        std::env::var("SENDGRID_API_KEY").unwrap_or_default(),
        std::env::var("SENDGRID_FROM_EMAIL").unwrap_or_default(),
    );

    let contact_receiver = std::env::var("CONTACT_EMAIL").unwrap_or("contact@example.com".into());

    if form.website.is_some() && !form.website.as_ref().unwrap().is_empty() {
        tracing::warn!("🕷️ Honeypot caught a bot attempt!");
        return StatusCode::OK.into_response();
    }

    let message = form.message.trim().to_lowercase();

    let spam_keywords: Vec<String> = std::env::var("SPAM_KEYWORDS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .collect();

    let message_lower = form.message.to_lowercase();

    let contains_spam_word = spam_keywords.iter().any(|kw| {
        if kw.contains(' ') {
            message_lower.contains(kw)
        } else {
            let pattern = format!(r"\b{}\b", regex::escape(kw));
            regex::Regex::new(&pattern).unwrap().is_match(&message_lower)
        }
    });

    let link_count = message.matches("http").count();
    let email_re = regex::Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap();
    let suspicious_email = email_re
        .find_iter(&message_lower)
        .any(|mat| mat.as_str() != form.email.to_lowercase());


    if message.len() < 10 || contains_spam_word || link_count > 0 || suspicious_email {
        tracing::warn!("🚫 Blocked suspicious contact message from {}: {:?}", form.email, form.message);

        let mut flash_cookie = Cookie::new("flash", "Your message looks suspicious and was blocked.");
        flash_cookie.set_path("/");
        flash_cookie.set_max_age(time::Duration::seconds(5));
        return (jar.add(flash_cookie), Redirect::to("/#contact")).into_response();
    }

    let client = reqwest::Client::new();
    let secret = std::env::var("RECAPTCHA_SECRET_KEY").unwrap_or_default();

    let verify_res = client
        .post("https://www.google.com/recaptcha/api/siteverify")
        .form(&[
            ("secret", secret.as_str()),
            ("response", form.recaptcha_token.as_str()),
        ])
        .send()
        .await;

    let Ok(resp) = verify_res else {
        tracing::warn!("❌ reCAPTCHA HTTP request failed");
        let mut flash_cookie = Cookie::new("flash", "reCAPTCHA verification failed.");
        flash_cookie.set_path("/");
        flash_cookie.set_max_age(time::Duration::seconds(5));
        return (jar.add(flash_cookie), Redirect::to("/")).into_response();
    };

    let Ok(json) = resp.json::<serde_json::Value>().await else {
        tracing::warn!("❌ reCAPTCHA JSON decode failed");
        let mut flash_cookie = Cookie::new("flash", "reCAPTCHA verification failed.");
        flash_cookie.set_path("/");
        flash_cookie.set_max_age(time::Duration::seconds(5));
        return (jar.add(flash_cookie), Redirect::to("/#contact")).into_response();
    };

    let success = json.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        tracing::warn!("❌ reCAPTCHA check failed: {:?}", json);
        let mut flash_cookie = Cookie::new("flash", "reCAPTCHA verification failed.");
        flash_cookie.set_path("/");
        flash_cookie.set_max_age(time::Duration::seconds(5));
        return (jar.add(flash_cookie), Redirect::to("/")).into_response();
    }

    let subject = format!("New Contact Message from {}", form.name);
    let body = format!(
        "<h2>New Contact Submission</h2>\
        <p><strong>Name:</strong> {}</p>\
        <p><strong>Email:</strong> {}</p>\
        <p><strong>Message:</strong><br>{}</p>",
        form.name,
        form.email,
        form.message.replace("\n", "<br>")
    );

    let send_result = sendgrid
        .send_raw_html(&contact_receiver, &subject, &body)
        .await;

    if let Err(e) = send_result {
        tracing::error!("❌ Failed to send contact email: {:?}", e);
        let mut flash_cookie = Cookie::new("flash", "There was a problem sending your message.");
        flash_cookie.set_path("/");
        flash_cookie.set_max_age(time::Duration::seconds(5));
        return (jar.add(flash_cookie), Redirect::to("/")).into_response();
    }

    tracing::info!("Contact message sent to {}", contact_receiver);

    let mut flash_cookie = Cookie::new("flash", "Thanks for reaching out! We'll get back to you soon.");
    flash_cookie.set_path("/");
    flash_cookie.set_max_age(time::Duration::seconds(5));

    (jar.add(flash_cookie), Redirect::to("/")).into_response()
}

#[axum::debug_handler]
pub async fn view_monitor_logs(
    State(state): State<AppState>,
    Extension(tera): Extension<tera::Tera>,
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

    let monitor_repo = MonitorRepository::new(&state.db);
    let status_log_repo = crate::db::status_log_repository::StatusLogRepository::new(&state.db);
    let user_repo = UserRepository::new(&state.db);

    let monitor = match monitor_repo.get_monitor_by_id(monitor_id, user_id).await {
        Ok(Some(m)) => m,
        _ => return Redirect::to("/dashboard").into_response(),
    };

    let user = match user_repo.get_user_by_id(user_id).await {
        Ok(Some(u)) => u,
        _ => return Redirect::to("/login").into_response(),
    };

    let logs = match status_log_repo.get_logs_by_monitor(monitor_id, 100).await {
        Ok(logs) => logs,
        Err(_) => vec![],
    };

    // 🕒 Format vremena (HH:MM)
    let time_format = parse("[hour]:[minute]").unwrap_or_else(|_| {
        panic!("Failed to parse time format for chart labels");
    });

    let chart_labels: Vec<String> = logs
        .iter()
        .map(|log| log.checked_at
            .map(|dt| dt.format(&time_format).unwrap_or_else(|_| "??:??".to_string()))
            .unwrap_or_else(|| "??:??".to_string()))
        .collect();


    // 📊 Response time (u32)
    let response_times: Vec<u32> = logs
        .iter()
        .map(|log| log.response_time_ms.unwrap_or(0).max(0) as u32)
        .collect();

    // 🧠 Kontekst za Tera šablon
    let mut ctx = Context::new();
    ctx.insert("logs", &logs);
    ctx.insert("monitor", &monitor);
    ctx.insert("current_user", &user_id);
    ctx.insert("user_name", &user.name);
    ctx.insert("user_plan", &user.plan);
    ctx.insert("chart_labels", &chart_labels);
    ctx.insert("response_times", &response_times);

    // 🧩 Render
    match tera.render("monitor_logs.html", &ctx) {
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
