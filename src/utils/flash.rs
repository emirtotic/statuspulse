use axum::{
    response::{IntoResponse, Redirect, Response},
    http::{header, HeaderMap},
};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use urlencoding::encode;

#[derive(Debug, Serialize, Deserialize)]
pub struct FlashMessage {
    pub message: String,
}

impl FlashMessage {
    pub fn error(msg: &str) -> Self {
        FlashMessage { message: msg.to_string() }
    }

    pub fn success(msg: &str) -> Self {
        FlashMessage { message: msg.to_string() }
    }

    pub fn redirect(self, location: &str) -> Response {
        let mut headers = HeaderMap::new();
        headers.insert(header::SET_COOKIE, format!("flash={}; Path=/; HttpOnly", encode(&self.message)).parse().unwrap());
        headers.insert(header::LOCATION, location.parse().unwrap());

        (StatusCode::SEE_OTHER, headers).into_response()
    }
}
