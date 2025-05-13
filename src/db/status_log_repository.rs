use crate::models::status_log::StatusLog;
use sqlx::{MySqlPool, Row};

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

    pub async fn get_last_status_log(&self, monitor_id: u64) -> Result<Option<StatusLog>, sqlx::Error> {
        let log = sqlx::query_as!(
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
        LIMIT 1
        "#,
        monitor_id
    )
            .fetch_optional(self.pool)
            .await?;

        Ok(log)
    }

    pub async fn get_uptime_percentage(&self, monitor_id: u64) -> Result<f64, sqlx::Error> {
        let row = sqlx::query(
            r#"
        SELECT
            COUNT(*) as total_count,
            SUM(CASE WHEN is_success = true THEN 1 ELSE 0 END) as success_count
        FROM status_logs
        WHERE monitor_id = ?
        "#
        )
            .bind(monitor_id)
            .fetch_one(self.pool)
            .await?;

        let total_count: i64 = row.try_get("total_count")?;
        let success_count: i64 = row.try_get::<Option<i64>, _>("success_count")?.unwrap_or(0);

        if total_count == 0 {
            Ok(0.0)
        } else {
            Ok((success_count as f64 / total_count as f64) * 100.0)
        }
    }



    pub async fn get_avg_response_time(&self, monitor_id: u64) -> Result<Option<f64>, sqlx::Error> {
        let avg_response_time: Option<Option<f64>> = sqlx::query_scalar!(
        r#"
        SELECT AVG(response_time_ms) as "avg_response_time_ms: Option<f64>"
        FROM status_logs
        WHERE monitor_id = ? AND is_success = true
        "#,
        monitor_id
    )
            .fetch_one(self.pool)
            .await?;

        Ok(avg_response_time.flatten())
    }




}
