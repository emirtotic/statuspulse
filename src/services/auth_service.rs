use crate::db::user_repository::UserRepository;
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

    /// REGISTER user (with JWT response)
    pub async fn register_user(&self, name: &str, email: &str, password: &str) -> Result<String, &'static str> {
        // Check if user already exists
        if let Ok(Some(_)) = self.repo.get_by_email(email).await {
            return Err("User already exists");
        }

        // Hash password with Argon2
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|_| "Failed to hash password")?
            .to_string();

        // Insert user into DB
        let user_id = self.repo.create_user(name, email, &password_hash)
            .await
            .map_err(|_| "Failed to create user")?;

        // Generate JWT token
        let claims = Claims {
            sub: user_id.to_string(),
            exp: (Utc::now() + Duration::hours(24)).timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        ).map_err(|_| "Failed to create token")?;

        Ok(token)
    }

    /// LOGIN user (return JWT token)
    pub async fn login_user(&self, email: &str, password: &str) -> Result<String, &'static str> {
        // Find user by email
        let user = self.repo.get_by_email(email).await
            .map_err(|_| "Database error")?
            .ok_or("Invalid credentials")?;

        // Verify password hash
        let parsed_hash = PasswordHash::new(&user.password_hash)
            .map_err(|_| "Invalid stored hash")?;

        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_err()
        {
            return Err("Invalid credentials");
        }

        // Generate JWT token
        let claims = Claims {
            sub: user.id.to_string(),
            exp: (Utc::now() + Duration::hours(24)).timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        ).map_err(|_| "Failed to create token")?;

        Ok(token)
    }
}
