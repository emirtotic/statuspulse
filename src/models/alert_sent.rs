use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use time::OffsetDateTime;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct AlertSent {

    pub id: u64,
    pub monitor_id: u64,
    pub sent_at: Option<OffsetDateTime>,
    pub alert_type: String,
    pub method: String,
}
