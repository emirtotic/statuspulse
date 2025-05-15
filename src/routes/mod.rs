use axum::{Router, routing::{get, post}};
use crate::{AppState, handlers::{auth_handler, axum_handler}};
pub mod monitor_routes;

pub fn api_auth_routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(auth_handler::login))
        .route("/register", post(auth_handler::register))
}

pub fn frontend_auth_routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(axum_handler::form_login).post(auth_handler::login))
        .route("/register", get(axum_handler::form_register).post(auth_handler::register))
        .route("/dashboard", get(axum_handler::dashboard))
        .route("/logout", get(axum_handler::logout))
        //.route("/monitors/new", get(axum_handler::form_create_monitor).post(axum_handler::form_create_monitor))
        // .route("/monitors/:id/edit", get(axum_handler::form_edit_monitor).post(axum_handler::form_edit_monitor))
        .route("/monitors/:id/delete", post(axum_handler::delete_monitor_form))
        .route("/monitors/new", get(axum_handler::form_create_monitor).post(axum_handler::create_monitor_form))
        .route("/monitors/:id/edit", get(axum_handler::form_edit_monitor).post(axum_handler::edit_monitor_form))



}

