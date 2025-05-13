use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use time::OffsetDateTime;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct StatusLog {

    pub id: u64,
    pub monitor_id: u64,
    pub checked_at: Option<OffsetDateTime>,
    pub response_code: Option<i32>,
    pub response_time_ms: Option<i32>,
    pub is_success: bool,
    pub error_msg: Option<String>,
}
