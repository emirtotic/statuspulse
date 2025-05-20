mod models;
mod db;
mod services;
mod handlers;
mod routes;
mod utils;

use axum::{Router, routing::get, Extension};
use std::{env, net::SocketAddr};
use axum::routing::get_service;
use dotenvy::dotenv;
use sqlx::{mysql::MySqlPoolOptions, migrate::Migrator};
use tracing_subscriber::{fmt, EnvFilter};
use services::worker;
use tera::Tera;
use tower_http::services::{ServeDir, ServeFile};
use crate::handlers::axum_handler::error_page;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::MySqlPool,
    pub jwt_secret: String,
    pub lemon_pro_url: String,
    pub lemon_enterprise_url: String,
}

fn build_tera() -> Tera {
    let mut tera = Tera::default();

    tera.add_raw_template("base.html", include_str!("templates/base.html")).unwrap();
    tera.add_raw_template("change_password.html", include_str!("templates/change_password.html")).unwrap();
    tera.add_raw_template("create_monitor.html", include_str!("templates/create_monitor.html")).unwrap();
    tera.add_raw_template("dashboard.html", include_str!("templates/dashboard.html")).unwrap();
    tera.add_raw_template("edit_monitor.html", include_str!("templates/edit_monitor.html")).unwrap();
    tera.add_raw_template("error.html", include_str!("templates/error.html")).unwrap();
    tera.add_raw_template("error_500.html", include_str!("templates/error_500.html")).unwrap();
    tera.add_raw_template("forgot_password.html", include_str!("templates/forgot_password.html")).unwrap();
    tera.add_raw_template("index.html", include_str!("templates/index.html")).unwrap();
    tera.add_raw_template("login.html", include_str!("templates/login.html")).unwrap();
    tera.add_raw_template("register.html", include_str!("templates/register.html")).unwrap();
    tera.add_raw_template("reset_password.html", include_str!("templates/reset_password.html")).unwrap();

    tera
}

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(true)
        .compact()
        .init();

    tracing::info!("Environment variables loaded.");

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    MIGRATOR.run(&pool).await?;
    tracing::info!("Migrations applied. DB is ready.");

    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let lemon_pro_url = env::var("LEMON_PRO_URL").expect("LEMON_PRO_URL must be set");
    let lemon_enterprise_url = env::var("LEMON_ENTERPRISE_URL").unwrap_or_default();

    let state = AppState {
        db: pool,
        jwt_secret,
        lemon_pro_url,
        lemon_enterprise_url,
    };

    let tera = build_tera();

    tokio::spawn(worker::start_worker(state.clone()));

    let app = Router::new()
        .nest(
            "/api",
            routes::monitor_routes::monitor_routes().with_state(state.clone())
        )
        .nest(
            "/auth",
            routes::api_auth_routes().with_state(state.clone())
        )
        .route("/robots.txt", get_service(ServeFile::new("static/robots.txt")))
        .nest_service("/static", ServeDir::new("static"))
        .nest("/webhook", routes::lemon_routes::lemon_routes().with_state(state.clone()))
        .nest("/", routes::frontend_auth_routes().with_state(state.clone()))
        .route("/health", get(health_check))
        .fallback(error_page)
        .layer(Extension(tera))
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
    tracing::info!("StatusPulse is listening on {}", addr);

    axum::serve(tokio::net::TcpListener::bind(addr).await?, app)
        .await
        .unwrap();

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}
