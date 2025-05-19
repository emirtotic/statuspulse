use crate::models::alert_sent::AlertSent;
use sqlx::{MySqlPool, Row};
use time::OffsetDateTime;

pub struct AlertSentRepository<'a> {
    pub pool: &'a MySqlPool,
}

impl<'a> AlertSentRepository<'a> {
    pub fn new(pool: &'a MySqlPool) -> Self {
        Self { pool }
    }

    pub async fn insert_alert(
        &self,
        monitor_id: u64,
        alert_type: &str, // 'email' | 'webhook'
        method: &str,     // npr. 'sendgrid'
        status: &str,     // 'down' | 'up'
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO alerts_sent (monitor_id, alert_type, method, status)
            VALUES (?, ?, ?, ?)
            "#
        )
            .bind(monitor_id)
            .bind(alert_type)
            .bind(method)
            .bind(status)
            .execute(self.pool)
            .await?;

        Ok(result.last_insert_id())
    }

    pub async fn was_recently_sent(
        &self,
        monitor_id: u64,
        alert_type: &str, // 'email' | 'webhook'
        status: &str,     // 'down' | 'up'
        since: OffsetDateTime,
    ) -> Result<bool, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM alerts_sent
            WHERE monitor_id = ? AND alert_type = ? AND status = ? AND sent_at >= ?
            "#
        )
            .bind(monitor_id)
            .bind(alert_type)
            .bind(status)
            .bind(since)
            .fetch_one(self.pool)
            .await?;

        let count: i64 = row.try_get("count")?;

        Ok(count > 0)
    }
}