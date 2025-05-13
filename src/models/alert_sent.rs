use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use crate::utils::datetime::serialize_offset_datetime;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct AlertSent {

    pub id: u64,
    pub monitor_id: u64,
    #[serde(serialize_with = "serialize_offset_datetime")]
    pub sent_at: Option<OffsetDateTime>,
    pub alert_type: String,
    pub method: String,
}
