use crate::db::user_repository::UserRepository;
use crate::models::user::User;
use sqlx::MySqlPool;
use argon2::{Argon2, PasswordHash, PasswordVerifier, password_hash::SaltString, PasswordHasher};
use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};
use rand_core::OsRng;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub struct AuthService<'a> {
    repo: UserRepository<'a>,
    jwt_secret: &'a str,
}

impl<'a> AuthService<'a> {
    pub fn new(pool: &'a MySqlPool, jwt_secret: &'a str) -> Self {
        Self {
            repo: UserRepository::new(pool),
            jwt_secret,
        }
    }

    pub async fn register_user(&self, name: &str, email: &str, password: &str) -> Result<u64, sqlx::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)
            .expect("Failed to hash password")
            .to_string();

        let user_id = self.repo.create_user(name, email, &password_hash).await?;
        Ok(user_id)
    }

    pub async fn login_user(&self, email: &str, password: &str) -> Result<String, &'static str> {
        let user = self.repo.get_by_email(email).await
            .map_err(|_| "Database error")?
            .ok_or("Invalid credentials")?;

        let parsed_hash = PasswordHash::new(&user.password_hash)
            .map_err(|_| "Invalid stored hash")?;

        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_err()
        {
            return Err("Invalid credentials");
        }

        let claims = Claims {
            sub: user.id.to_string(),
            exp: (Utc::now() + Duration::hours(24)).timestamp() as usize,
        };

        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(self.jwt_secret.as_bytes()))
            .map_err(|_| "Failed to create token")?;

        Ok(token)
    }
}
