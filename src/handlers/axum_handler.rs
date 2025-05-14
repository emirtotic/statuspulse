use axum::{Extension, response::Html};
use axum_extra::extract::cookie::CookieJar;
use tera::Tera;

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
