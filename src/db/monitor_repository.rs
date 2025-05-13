use crate::models::monitor::Monitor;
use sqlx::{MySqlPool, Row};

pub struct MonitorRepository<'a> {
    pub pool: &'a MySqlPool,
}

impl<'a> MonitorRepository<'a> {
    pub fn new(pool: &'a MySqlPool) -> Self {
        Self { pool }
    }

    pub async fn get_all_by_user(&self, user_id: u64) -> Result<Vec<Monitor>, sqlx::Error> {
        tracing::info!("Querying monitors for user_id: {}", user_id);

        let rows = sqlx::query(
            r#"
            SELECT id, user_id, label, url, interval_mins, is_active, created_at
            FROM monitors
            WHERE user_id = ?
            "#
        )
            .bind(user_id)
            .fetch_all(self.pool)
            .await?;

        let monitors = rows.into_iter().map(|row| {
            Monitor {
                id: row.try_get("id").unwrap(),
                user_id: row.try_get("user_id").unwrap(),
                label: row.try_get("label").unwrap(),
                url: row.try_get("url").unwrap(),
                interval_mins: row.try_get("interval_mins").unwrap(),
                is_active: row.try_get("is_active").unwrap(),
                created_at: row.try_get("created_at").ok(),
            }
        }).collect();

        Ok(monitors)
    }

    pub async fn create_monitor(
        &self,
        user_id: u64,
        label: &str,
        url: &str,
        interval_mins: i32
    ) -> Result<u64, sqlx::Error> {
        tracing::info!("Creating monitor -> user_id: {}, label: '{}', url: '{}', interval: {} mins", user_id, label, url, interval_mins);

        let result = sqlx::query(
            r#"
            INSERT INTO monitors (user_id, label, url, interval_mins, is_active)
            VALUES (?, ?, ?, ?, true)
            "#
        )
            .bind(user_id)
            .bind(label)
            .bind(url)
            .bind(interval_mins)
            .execute(self.pool)
            .await?;

        tracing::info!("✅ Monitor created with id: {}", result.last_insert_id());

        Ok(result.last_insert_id())
    }

    pub async fn delete_monitor(&self, monitor_id: u64, user_id: u64) -> Result<u64, sqlx::Error> {
        tracing::info!("Deleting monitor_id: {} for user_id: {}", monitor_id, user_id);

        let result = sqlx::query(
            r#"
            DELETE FROM monitors
            WHERE id = ? AND user_id = ?
            "#
        )
            .bind(monitor_id)
            .bind(user_id)
            .execute(self.pool)
            .await?;

        if result.rows_affected() > 0 {
            tracing::info!("✅ Deleted monitor_id: {}", monitor_id);
        } else {
            tracing::warn!("⚠️ No monitor found to delete with id: {}", monitor_id);
        }

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
        tracing::info!("Updating monitor_id: {} for user_id: {}", monitor_id, user_id);

        let result = sqlx::query(
            r#"
            UPDATE monitors
            SET label = ?, url = ?, interval_mins = ?, is_active = ?
            WHERE id = ? AND user_id = ?
            "#
        )
            .bind(label)
            .bind(url)
            .bind(interval_mins)
            .bind(is_active)
            .bind(monitor_id)
            .bind(user_id)
            .execute(self.pool)
            .await?;

        if result.rows_affected() > 0 {
            tracing::info!("✅ Updated monitor_id: {}", monitor_id);
        } else {
            tracing::warn!("⚠️ No monitor found to update with id: {}", monitor_id);
        }

        Ok(result.rows_affected())
    }

    pub async fn get_monitor_by_id(&self, monitor_id: u64, user_id: u64) -> Result<Option<Monitor>, sqlx::Error> {
        tracing::info!("Fetching monitor_id {} for user_id {}", monitor_id, user_id);

        let row = sqlx::query(
            r#"
            SELECT id, user_id, label, url, interval_mins, is_active, created_at
            FROM monitors
            WHERE id = ? AND user_id = ?
            "#
        )
            .bind(monitor_id)
            .bind(user_id)
            .fetch_optional(self.pool)
            .await?;

        if let Some(row) = row {
            let monitor = Monitor {
                id: row.try_get("id")?,
                user_id: row.try_get("user_id")?,
                label: row.try_get("label")?,
                url: row.try_get("url")?,
                interval_mins: row.try_get("interval_mins")?,
                is_active: row.try_get("is_active")?,
                created_at: row.try_get("created_at").ok(),
            };
            Ok(Some(monitor))
        } else {
            Ok(None)
        }
    }
}
