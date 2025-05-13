use crate::models::status_log::StatusLog;
use sqlx::MySqlPool;

pub struct StatusLogRepository<'a> {
    pub pool: &'a MySqlPool,
}

impl<'a> StatusLogRepository<'a> {
    pub fn new(pool: &'a MySqlPool) -> Self {
        Self { pool }
    }

    pub async fn insert_log(
        &self,
        monitor_id: u64,
        response_code: Option<i32>,
        response_time_ms: Option<i32>,
        is_success: bool,
        error_msg: Option<String>,
    ) -> Result<u64, sqlx::Error> {
        tracing::info!(
            "Inserting status log -> monitor_id: {}, code: {:?}, time_ms: {:?}, success: {}, error: {:?}",
            monitor_id, response_code, response_time_ms, is_success, error_msg
        );

        let result = sqlx::query!(
            r#"
            INSERT INTO status_logs (monitor_id, response_code, response_time_ms, is_success, error_msg)
            VALUES (?, ?, ?, ?, ?)
            "#,
            monitor_id,
            response_code,
            response_time_ms,
            is_success,
            error_msg
        )
            .execute(self.pool)
            .await?;

        Ok(result.last_insert_id())
    }

    pub async fn get_logs_by_monitor(
        &self,
        monitor_id: u64,
        limit: u32,
    ) -> Result<Vec<StatusLog>, sqlx::Error> {
        tracing::info!("Fetching last {} logs for monitor_id {}", limit, monitor_id);

        let logs = sqlx::query_as!(
        StatusLog,
        r#"
        SELECT
            id,
            monitor_id,
            checked_at,
            response_code,
            response_time_ms,
            is_success as "is_success: bool",
            error_msg
        FROM status_logs
        WHERE monitor_id = ?
        ORDER BY checked_at DESC
        LIMIT ?
        "#,
        monitor_id,
        limit
    )
            .fetch_all(self.pool)
            .await?;

        Ok(logs)
    }

}
