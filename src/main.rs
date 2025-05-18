mod models;
mod db;
mod services;
mod handlers;
mod routes;
mod utils;

use axum::{Router, routing::get, Extension};
use std::{env, net::SocketAddr};
use dotenvy::dotenv;
use sqlx::{mysql::MySqlPoolOptions, migrate::Migrator};
use tracing_subscriber::{fmt, EnvFilter};
use services::worker;
use tera::Tera;
use tower_http::services::ServeDir;
use crate::handlers::axum_handler::error_page;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::MySqlPool,
    pub jwt_secret: String,
    pub lemon_pro_url: String,
    pub lemon_enterprise_url: String,
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

    // Tera templates
    let tera = Tera::new("src/templates/**/*").expect("Failed to load templates");

    // Start ping worker in background
    tokio::spawn(worker::start_worker(state.clone()));

    // Full router
    let app = Router::new()
        .nest(
            "/api",
            routes::monitor_routes::monitor_routes().with_state(state.clone())
        )
        .nest(
            "/auth",
            routes::api_auth_routes().with_state(state.clone())
        )
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
