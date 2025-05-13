use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use crate::models::status_log::StatusLog;
use crate::utils::datetime::serialize_offset_datetime;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Monitor {
    pub id: u64,
    pub user_id: u64,
    pub label: String,
    pub url: String,
    pub interval_mins: i32,
    pub is_active: bool,
    #[serde(serialize_with = "serialize_offset_datetime")]
    pub created_at: Option<OffsetDateTime>,
}

#[derive(Serialize)]
pub struct MonitorStatusSummary {
    pub monitor_id: u64,
    pub last_status: Option<StatusLog>,
    pub uptime_percentage: f64,
    pub average_response_time_ms: Option<f64>,
}

