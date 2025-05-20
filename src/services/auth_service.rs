use crate::db::user_repository::UserRepository;
use crate::models::user::User;
use sqlx::MySqlPool;
use argon2::{Argon2, PasswordHash, PasswordVerifier, password_hash::SaltString, PasswordHasher};
use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};
use rand_core::OsRng;
use thiserror::Error;
use crate::services::sendgrid_service::SendGridService;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Error, Serialize, Deserialize)]
pub enum AuthError {
    #[error("User already exists")]
    UserExists,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Database error")]
    DatabaseError,
    #[error("Hashing failed")]
    HashingError,
    #[error("Token generation failed")]
    TokenError,
}

pub struct AuthService<'a> {
    repo: UserRepository<'a>,
    jwt_secret: &'a str,
    pub sendgrid: SendGridService,
}

impl<'a> AuthService<'a> {
    pub fn new(pool: &'a MySqlPool, jwt_secret: &'a str, sendgrid: SendGridService) -> Self {
        Self {
            repo: UserRepository::new(pool),
            jwt_secret,
            sendgrid,
        }
    }

    pub async fn register_user(&self, name: &str, email: &str, password: &str) -> Result<String, AuthError> {

        if let Ok(Some(_)) = self.repo.get_by_email(email).await {
            return Err(AuthError::UserExists);
        }

        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| AuthError::HashingError)?
            .to_string();

        let user_id = self.repo.create_user(name, email, &password_hash, "free")
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        let email_result = self.sendgrid.send_alert(
            email,
            "Welcome to StatusPulse!",
            "src/services/email_templates/email_registration.html",
            &[("USER_NAME", name)],
        ).await;

        if let Err(e) = email_result {
            tracing::warn!("Failed to send registration email to {}: {}", email, e);
        }

        self.generate_token(user_id)
    }

    pub async fn login_user(&self, email: &str, password: &str) -> Result<String, AuthError> {
        let user = self.repo.get_by_email(email).await
            .map_err(|_| AuthError::DatabaseError)?
            .ok_or(AuthError::InvalidCredentials)?;

        let parsed_hash = PasswordHash::new(&user.password_hash)
            .map_err(|_| AuthError::HashingError)?;

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::InvalidCredentials)?;

        self.generate_token(user.id)
    }

    fn generate_token(&self, user_id: u64) -> Result<String, AuthError> {
        let claims = Claims {
            sub: user_id.to_string(),
            exp: (Utc::now() + Duration::hours(24)).timestamp() as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        ).map_err(|_| AuthError::TokenError)
    }

    pub async fn send_password_changed_email(&self, email: &str, name: &str) -> Result<(), anyhow::Error> {
        self.sendgrid
            .send_password_changed_notification(email, name)
            .await
            .map_err(|e| anyhow::anyhow!("SendGrid error: {}", e))
    }

}
