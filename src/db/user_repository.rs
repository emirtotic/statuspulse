use bcrypt::verify;
use crate::models::user::User;
use sqlx::{MySqlPool, Row};

pub struct UserRepository<'a> {
    pub pool: &'a MySqlPool,
}

impl<'a> UserRepository<'a> {
    pub fn new(pool: &'a MySqlPool) -> Self {
        Self { pool }
    }

    pub async fn authenticate_user(&self, email: &str, password: &str) -> Result<Option<User>, sqlx::Error> {
        if let Some(user) = self.get_by_email(email).await? {

            match verify(password, &user.password_hash) {
                Ok(true) => Ok(Some(user)),
                Ok(false) => Ok(None),
                Err(_) => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    pub async fn get_by_email(&self, email: &str) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, name, email, password_hash, plan, created_at
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
                plan: row.try_get("plan")?,
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

    pub async fn create_user(&self, name: &str, email: &str, password_hash: &str, plan: &str) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO users (name, email, password_hash, plan)
            VALUES (?, ?, ?, ?)
            "#
        )
            .bind(name)
            .bind(email)
            .bind(password_hash)
            .bind(plan)
            .execute(self.pool)
            .await?;

        Ok(result.last_insert_id())
    }

    pub async fn get_user_plan(&self, user_id: u64) -> Result<Option<String>, sqlx::Error> {
        let rec = sqlx::query!(
        "SELECT plan FROM users WHERE id = ?",
        user_id
    )
            .fetch_optional(&*self.pool)
            .await?;

        Ok(rec.map(|r| r.plan))
    }

    pub async fn get_user_by_id(&self, user_id: u64) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query(
            r#"
        SELECT id, name, email, password_hash, plan, created_at
        FROM users
        WHERE id = ?
        "#
        )
            .bind(user_id)
            .fetch_optional(self.pool)
            .await?;

        if let Some(row) = row {
            let user = User {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                email: row.try_get("email")?,
                password_hash: row.try_get("password_hash")?,
                plan: row.try_get("plan")?,
                created_at: row.try_get("created_at")?,
            };
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    pub async fn update_user_plan(&self, user_id: u64, new_plan: &str) -> Result<(), sqlx::Error> {
        sqlx::query!(
        "UPDATE users SET plan = ? WHERE id = ?",
        new_plan,
        user_id
    )
            .execute(self.pool)
            .await?;

        Ok(())
    }



}
