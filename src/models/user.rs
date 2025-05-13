use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use sqlx::types::time::OffsetDateTime;
use crate::utils::datetime::serialize_offset_datetime;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {

    pub id: u64,
    pub name: String,
    pub email: String,
    pub password_hash: String,
    #[serde(serialize_with = "serialize_offset_datetime")]
    pub created_at: Option<OffsetDateTime>,
}
