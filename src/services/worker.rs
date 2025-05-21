use crate::{
    db::{
        monitor_repository::MonitorRepository,
        status_log_repository::StatusLogRepository,
        alert_sent_repository::AlertSentRepository,
    },
    services::sendgrid_service::SendGridService,
    AppState,
};
use reqwest::Client;
use std::{collections::HashMap, sync::Arc, time::Instant};
use tokio::time::{sleep, Duration};
use tracing::{info, error};
use futures::future::join_all;
use time::{OffsetDateTime, Duration as TimeDuration};
use tokio::sync::Mutex;

pub async fn start_worker(state: AppState) {
    tokio::spawn(async move {
        let client = Client::new();

        let monitor_repo = Arc::new(MonitorRepository::new(&state.db));
        let status_log_repo = Arc::new(StatusLogRepository::new(&state.db));
        let alerts_repo = Arc::new(AlertSentRepository::new(&state.db));

        let sendgrid_service = Arc::new(SendGridService::new(
            std::env::var("SENDGRID_API_KEY").expect("SENDGRID_API_KEY must be set"),
            std::env::var("SENDGRID_FROM_EMAIL").expect("SENDGRID_FROM_EMAIL must be set"),
        ));

        let next_check_times = Arc::new(Mutex::new(HashMap::<u64, OffsetDateTime>::new()));

        loop {
            info!("Starting monitor ping cycle...");

            match monitor_repo.get_all_active().await {
                Ok(monitors) => {
                    info!("Found {} active monitors", monitors.len());

                    let tasks = monitors.into_iter().map(|monitor| {
                        let client = client.clone();
                        let monitor_repo = Arc::clone(&monitor_repo);
                        let status_log_repo = Arc::clone(&status_log_repo);
                        let alerts_repo = Arc::clone(&alerts_repo);
                        let sendgrid_service = Arc::clone(&sendgrid_service);
                        let next_check_times = Arc::clone(&next_check_times);

                        async move {
                            let now = OffsetDateTime::now_utc();

                            {
                                let mut map = next_check_times.lock().await;
                                if let Some(next_check) = map.get(&monitor.id) {
                                    if &now < next_check {
                                        return;
                                    }
                                }
                                map.insert(monitor.id, now + TimeDuration::minutes(monitor.interval_mins.into()));
                            }

                            let url = monitor.url.clone();
                            let monitor_id = monitor.id;

                            let start = Instant::now();
                            let response = client.get(&url)
                                .timeout(Duration::from_secs(10))
                                .send()
                                .await;

                            let duration_ms = start.elapsed().as_millis() as i32;
                            let since = OffsetDateTime::now_utc() - TimeDuration::hours(8);

                            match response {
                                Ok(resp) => {
                                    let status_code = resp.status().as_u16() as i32;
                                    info!("Monitor {} responded with {} in {}ms", url, status_code, duration_ms);

                                    let _ = status_log_repo.insert_log(
                                        monitor_id,
                                        Some(status_code),
                                        Some(duration_ms),
                                        true,
                                        None,
                                    ).await;

                                    let _ = monitor_repo.update_is_up(monitor_id, true).await;

                                    if let Ok(Some(user)) = monitor_repo.get_monitor_owner(monitor_id).await {
                                        if let Ok(false) = alerts_repo.was_recently_sent(monitor_id, "email", "up", since).await {
                                            let subject = format!("Monitor RECOVERED: {}", monitor.label);
                                            let replacements = &[
                                                ("USER_NAME", user.name.as_str()),
                                                ("MONITOR_LABEL", monitor.label.as_str()),
                                                ("MONITOR_URL", monitor.url.as_str()),
                                            ];

                                            if let Err(e) = sendgrid_service
                                                .send_alert(
                                                    &user.email,
                                                    &subject,
                                                    "src/services/email_templates/email_monitor_up.html",
                                                    replacements,
                                                ).await {
                                                error!("Failed to send recovery email: {:?}", e);
                                            } else {
                                                let _ = alerts_repo.insert_alert(monitor_id, "email", "sendgrid", "up").await;
                                            }
                                        }
                                    }
                                }

                                Err(e) => {
                                    error!("Error pinging {}: {:?}", url, e);

                                    let _ = status_log_repo.insert_log(
                                        monitor_id,
                                        None,
                                        None,
                                        false,
                                        Some(e.to_string()),
                                    ).await;

                                    let _ = monitor_repo.update_is_up(monitor_id, false).await;

                                    if let Ok(Some(user)) = monitor_repo.get_monitor_owner(monitor_id).await {
                                        if let Ok(false) = alerts_repo.was_recently_sent(monitor_id, "email", "down", since).await {
                                            let subject = format!("Monitor DOWN: {}", monitor.label);
                                            let replacements = &[
                                                ("USER_NAME", user.name.as_str()),
                                                ("MONITOR_LABEL", monitor.label.as_str()),
                                                ("MONITOR_URL", monitor.url.as_str()),
                                            ];

                                            if let Err(e) = sendgrid_service
                                                .send_alert(
                                                    &user.email,
                                                    &subject,
                                                    "src/services/email_templates/email_monitor_down.html",
                                                    replacements,
                                                ).await {
                                                error!("Failed to send down alert email: {:?}", e);
                                            } else {
                                                let _ = alerts_repo.insert_alert(monitor_id, "email", "sendgrid", "down").await;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    });

                    join_all(tasks).await;
                }
                Err(e) => {
                    error!("Failed to fetch monitors: {:?}", e);
                }
            }

            info!("Sleeping 900 seconds before next cycle...");
            sleep(Duration::from_secs(900)).await;
        }
    });
}