use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {

    pub id: u64,
    pub name: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
}
