use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use time::OffsetDateTime;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Monitor {
    pub id: u64,
    pub user_id: u64,
    pub label: String,
    pub url: String,
    pub interval_mins: i32,
    pub is_active: bool,
    pub created_at: Option<OffsetDateTime>,
}
