use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use sqlx::types::time::OffsetDateTime;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {

    pub id: u64,
    pub name: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: Option<OffsetDateTime>,
}
