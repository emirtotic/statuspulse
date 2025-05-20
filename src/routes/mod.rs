use axum::{Router, routing::{get, post}};
use crate::{AppState, handlers::{auth_handler, axum_handler}};
use crate::handlers::{change_password, checkout_handler};

pub mod monitor_routes;
pub mod lemon_routes;

pub fn api_auth_routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(auth_handler::login))
        .route("/register", post(auth_handler::register))
        .route("/forgot-password", get(auth_handler::form_forgot_password))
        .route("/forgot-password", post(change_password::process_forgot_password))
}

pub fn frontend_auth_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(axum_handler::landing_page))
        .route("/login", get(axum_handler::form_login).post(auth_handler::login))
        .route("/register", get(axum_handler::form_register).post(auth_handler::register))
        .route("/dashboard", get(axum_handler::dashboard))
        .route("/logout", get(axum_handler::logout))
        .route("/monitors/new", get(axum_handler::form_create_monitor).post(axum_handler::create_monitor_form))
        .route("/monitors/:id/edit", get(axum_handler::form_edit_monitor).post(axum_handler::edit_monitor_form))
        .route("/monitors/:id/delete", post(axum_handler::delete_monitor_form))
        .route("/checkout/:plan", get(checkout_handler::checkout_handler))
        .route("/error", get(axum_handler::error_page))
        .route("/contact", post(axum_handler::submit_contact_form))
        // password change routes
        .route("/settings/change-password", get(change_password::change_password_form))
        .route("/settings/change-password", post(change_password::process_password_change))
        .route("/forgot-password", get(auth_handler::form_forgot_password).post(change_password::process_forgot_password))
        .route("/reset-password/:token", get(auth_handler::form_reset_password))
        .route("/reset-password/:token", post(change_password::process_reset_password))

}


