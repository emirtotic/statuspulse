use crate::models::alert_sent::AlertSent;
use sqlx::MySqlPool;
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
        alert_type: &str, // email or webhook
        method: &str,     // sendgrid | slack_webhook | etc.
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            INSERT INTO alerts_sent (monitor_id, alert_type, method)
            VALUES (?, ?, ?)
            "#,
            monitor_id,
            alert_type,
            method
        )
            .execute(self.pool)
            .await?;

        Ok(result.last_insert_id())
    }

    pub async fn was_recently_sent(
        &self,
        monitor_id: u64,
        alert_type: &str,
        since: OffsetDateTime,
    ) -> Result<bool, sqlx::Error> {
        let count = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as count
        FROM alerts_sent
        WHERE monitor_id = ? AND alert_type = ? AND sent_at >= ?
        "#,
        monitor_id,
        alert_type,
        since
    )
            .fetch_one(self.pool)
            .await?;

        Ok(count > 0)
    }
}
