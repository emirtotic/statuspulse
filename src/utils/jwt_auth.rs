use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode, header::AUTHORIZATION},
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::Deserialize;
use crate::AppState;
use std::any::Any;

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
    S: Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        tracing::info!("🔐 Starting JWT extraction...");

        // Downcast state to AppState
        let state = (state as &dyn Any)
            .downcast_ref::<AppState>()
            .ok_or_else(|| {
                tracing::error!("Failed to downcast state to AppState");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Extract Authorization header manually
        let auth_header = match parts.headers.get(AUTHORIZATION) {
            Some(value) => match value.to_str() {
                Ok(val) => val,
                Err(e) => {
                    tracing::error!("Invalid Authorization header encoding: {:?}", e);
                    return Err(StatusCode::UNAUTHORIZED);
                }
            },
            None => {
                tracing::warn!("Missing Authorization header.");
                return Err(StatusCode::UNAUTHORIZED);
            }
        };

        // Must start with "Bearer "
        let token = match auth_header.strip_prefix("Bearer ") {
            Some(token) => token,
            None => {
                tracing::warn!("Authorization header does not start with 'Bearer ' prefix.");
                return Err(StatusCode::UNAUTHORIZED);
            }
        };

        tracing::info!("JWT token received, verifying...");

        // Decode JWT
        let token_data = match decode::<Claims>(
            token,
            &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        ) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Failed to decode JWT token: {:?}", e);
                return Err(StatusCode::UNAUTHORIZED);
            }
        };

        // Parse user_id from sub
        let user_id = match token_data.claims.sub.parse::<u64>() {
            Ok(id) => id,
            Err(e) => {
                tracing::error!("Failed to parse user_id from token sub claim: {:?}", e);
                return Err(StatusCode::UNAUTHORIZED);
            }
        };

        tracing::info!("Authenticated user_id: {}", user_id);

        Ok(CurrentUser { user_id })
    }
}
