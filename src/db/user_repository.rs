use crate::models::user::User;
use sqlx::{MySqlPool, Row};

pub struct UserRepository<'a> {
    pub pool: &'a MySqlPool,
}

impl<'a> UserRepository<'a> {
    pub fn new(pool: &'a MySqlPool) -> Self {
        Self { pool }
    }

    pub async fn get_by_email(&self, email: &str) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, name, email, password_hash, created_at
            FROM users
            WHERE email = ?
            "#,
            email
        )
            .fetch_optional(self.pool)
            .await?;

        Ok(user)
    }

    pub async fn exists_by_id(&self, user_id: u64) -> Result<bool, sqlx::Error> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) as count FROM users WHERE id = ?"
        )
            .bind(user_id)
            .fetch_one(self.pool)
            .await?;

        Ok(count.0 > 0)
    }

    pub async fn create_user(&self, name: &str, email: &str, password_hash: &str) -> Result<u64, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            INSERT INTO users (name, email, password_hash)
            VALUES (?, ?, ?)
            "#,
            name,
            email,
            password_hash
        )
            .execute(self.pool)
            .await?;

        Ok(result.last_insert_id())
    }
}
