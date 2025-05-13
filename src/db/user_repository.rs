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
        let row = sqlx::query(
            r#"
            SELECT id, name, email, password_hash, created_at
            FROM users
            WHERE email = ?
            "#
        )
            .bind(email)
            .fetch_optional(self.pool)
            .await?;

        if let Some(row) = row {
            let user = User {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                email: row.try_get("email")?,
                password_hash: row.try_get("password_hash")?,
                created_at: row.try_get("created_at")?,
            };
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    pub async fn exists_by_id(&self, user_id: u64) -> Result<bool, sqlx::Error> {
        let count: (i64,) = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) as count FROM users WHERE id = ?"
        )
            .bind(user_id)
            .fetch_one(self.pool)
            .await?;

        Ok(count.0 > 0)
    }

    pub async fn create_user(&self, name: &str, email: &str, password_hash: &str) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO users (name, email, password_hash)
            VALUES (?, ?, ?)
            "#
        )
            .bind(name)
            .bind(email)
            .bind(password_hash)
            .execute(self.pool)
            .await?;

        Ok(result.last_insert_id())
    }
}
