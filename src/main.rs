use axum::{Router, routing::get, serve};
use std::{env, net::SocketAddr};
use dotenvy::dotenv;
use sqlx::{mysql::MySqlPoolOptions, migrate::Migrator};
use tracing_subscriber;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {

    dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();


    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    MIGRATOR.run(&pool).await?;

    tracing::info!("Migrations applied. Starting StatusPulse server...");

    let app = Router::new()
        .route("/health", get(health_check));

    let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();

    tracing::info!("Listening on {}", addr);

    axum::serve(tokio::net::TcpListener::bind(addr).await?, app)
        .await
        .unwrap();

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}
