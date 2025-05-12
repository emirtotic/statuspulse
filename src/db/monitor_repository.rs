use crate::models::monitor::Monitor;
use sqlx::MySqlPool;

pub struct MonitorRepository<'a> {
    pub pool: &'a MySqlPool,
}

impl<'a> MonitorRepository<'a> {
    pub fn new(pool: &'a MySqlPool) -> Self {
        Self { pool }
    }

    pub async fn get_all_by_user(&self, user_id: u64) -> Result<Vec<Monitor>, sqlx::Error> {
        tracing::info!("Querying monitors for user_id: {}", user_id);

        let monitors = sqlx::query_as!(
        Monitor,
        r#"
        SELECT
            id,
            user_id,
            label,
            url,
            interval_mins,
            is_active as "is_active: bool",
            created_at
        FROM monitors
        WHERE user_id = ?
        "#,
        user_id
    )
            .fetch_all(self.pool)
            .await
            .map_err(|e| {
                tracing::error!("SQLx error fetching monitors for user_id {}: {:?}", user_id, e);
                e
            })?;

        Ok(monitors)
    }


    pub async fn create_monitor(
        &self,
        user_id: u64,
        label: &str,
        url: &str,
        interval_mins: i32
    ) -> Result<u64, sqlx::Error> {
        tracing::info!(
        "Creating monitor -> user_id: {}, label: '{}', url: '{}', interval: {} mins",
        user_id, label, url, interval_mins
    );

        let result = match sqlx::query!(
        r#"
        INSERT INTO monitors (user_id, label, url, interval_mins, is_active)
        VALUES (?, ?, ?, ?, true)
        "#,
        user_id,
        label,
        url,
        interval_mins
    )
            .execute(self.pool)
            .await {
            Ok(res) => {
                tracing::info!("Successfully created monitor for user_id: {} with id: {}", user_id, res.last_insert_id());
                res
            },
            Err(e) => {
                tracing::error!("Failed to create monitor for user_id: {}. Error: {:?}", user_id, e);
                return Err(e);
            }
        };

        Ok(result.last_insert_id())
    }


    pub async fn delete_monitor(
        &self,
        monitor_id: u64,
        user_id: u64
    ) -> Result<u64, sqlx::Error> {
        tracing::info!(
        "Deleting monitor -> monitor_id: {}, user_id: {}",
        monitor_id, user_id
    );

        let result = match sqlx::query!(
        r#"
        DELETE FROM monitors
        WHERE id = ? AND user_id = ?
        "#,
        monitor_id,
        user_id
    )
            .execute(self.pool)
            .await {
            Ok(res) => {
                if res.rows_affected() > 0 {
                    tracing::info!(
                    "Successfully deleted monitor_id: {} for user_id: {}. Rows affected: {}",
                    monitor_id,
                    user_id,
                    res.rows_affected()
                );
                } else {
                    tracing::warn!(
                    "No monitor found to delete with monitor_id: {} for user_id: {}",
                    monitor_id,
                    user_id
                );
                }
                res
            },
            Err(e) => {
                tracing::error!(
                "Failed to delete monitor_id: {} for user_id: {}. Error: {:?}",
                monitor_id,
                user_id,
                e
            );
                return Err(e);
            }
        };

        Ok(result.rows_affected())
    }

    pub async fn update_monitor(
        &self,
        monitor_id: u64,
        user_id: u64,
        label: &str,
        url: &str,
        interval_mins: i32,
        is_active: bool,
    ) -> Result<u64, sqlx::Error> {
        tracing::info!(
        "Updating monitor -> monitor_id: {}, user_id: {}, label: '{}', url: '{}', interval_mins: {}, is_active: {}",
        monitor_id,
        user_id,
        label,
        url,
        interval_mins,
        is_active
    );

        let result = match sqlx::query!(
        r#"
        UPDATE monitors
        SET label = ?, url = ?, interval_mins = ?, is_active = ?
        WHERE id = ? AND user_id = ?
        "#,
        label,
        url,
        interval_mins,
        is_active,
        monitor_id,
        user_id
    )
            .execute(self.pool)
            .await {
            Ok(res) => {
                if res.rows_affected() > 0 {
                    tracing::info!(
                    "Successfully updated monitor_id: {} for user_id: {}. Rows affected: {}",
                    monitor_id,
                    user_id,
                    res.rows_affected()
                );
                } else {
                    tracing::warn!(
                    "No monitor found to update with monitor_id: {} for user_id: {}",
                    monitor_id,
                    user_id
                );
                }
                res
            },
            Err(e) => {
                tracing::error!(
                "Failed to update monitor_id: {} for user_id: {}. Error: {:?}",
                monitor_id,
                user_id,
                e
            );
                return Err(e);
            }
        };

        Ok(result.rows_affected())
    }

    pub async fn get_monitor_by_id(&self, monitor_id: u64, user_id: u64) -> Result<Option<Monitor>, sqlx::Error> {
        tracing::info!("Fetching monitor_id {} for user_id {}", monitor_id, user_id);

        let monitor = sqlx::query_as!(
        Monitor,
        r#"
        SELECT
            id,
            user_id,
            label,
            url,
            interval_mins,
            is_active as "is_active: bool",
            created_at
        FROM monitors
        WHERE id = ? AND user_id = ?
        "#,
        monitor_id,
        user_id
    )
            .fetch_optional(self.pool)
            .await?;

        Ok(monitor)
    }



}
