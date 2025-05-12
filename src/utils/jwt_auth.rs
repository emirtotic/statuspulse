use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode, header::AUTHORIZATION},
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::Deserialize;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Debug)]
pub struct CurrentUser {
    pub user_id: u64,
}

#[async_trait]
impl<S> FromRequestParts<S> for CurrentUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract AppState
        let state = parts
            .extensions
            .get::<AppState>()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

        // Extract Authorization header manually
        let auth_header = parts.headers.get(AUTHORIZATION)
            .ok_or(StatusCode::UNAUTHORIZED)?
            .to_str()
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        // Must start with "Bearer "
        let token = auth_header.strip_prefix("Bearer ")
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // Decode JWT
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        let user_id = token_data.claims.sub.parse::<u64>()
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        Ok(CurrentUser { user_id })
    }
}
