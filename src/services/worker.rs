use crate::{
    db::{monitor_repository::MonitorRepository, status_log_repository::StatusLogRepository, alert_sent_repository::AlertSentRepository},
    AppState,
};
use reqwest::Client;
use std::{sync::Arc, time::Instant};
use tokio::time::{sleep, Duration};
use tracing::{info, error};
use futures::future::join_all;
use time::{OffsetDateTime, Duration as TimeDuration};

pub async fn start_worker(state: AppState) {
    tokio::spawn(async move {
        let client = Client::new();
        let monitor_repo = MonitorRepository::new(&state.db);
        let status_log_repo = Arc::new(StatusLogRepository::new(&state.db));
        let alerts_repo = Arc::new(AlertSentRepository::new(&state.db));

        loop {
            info!("Starting monitor ping cycle...");

            match monitor_repo.get_all_active().await {
                Ok(monitors) => {
                    info!("Found {} active monitors", monitors.len());

                    let tasks = monitors.into_iter().map(|monitor| {
                        let client = client.clone();
                        let status_log_repo = Arc::clone(&status_log_repo);
                        let alerts_repo = Arc::clone(&alerts_repo);

                        async move {
                            let url = monitor.url.clone();
                            let monitor_id = monitor.id;

                            let start = Instant::now();
                            let response = client.get(&url)
                                .timeout(Duration::from_secs(10))
                                .send()
                                .await;

                            let duration_ms = start.elapsed().as_millis() as i32;

                            match response {
                                Ok(resp) => {
                                    let status_code = resp.status().as_u16() as i32;
                                    info!("Monitor {} responded with {} in {}ms", url, status_code, duration_ms);

                                    if let Err(e) = status_log_repo.insert_log(
                                        monitor_id,
                                        Some(status_code),
                                        Some(duration_ms),
                                        true,
                                        None,
                                    ).await {
                                        error!("Failed to insert status log: {:?}", e);
                                    }
                                }
                                Err(e) => {
                                    error!("Error pinging {}: {:?}", url, e);

                                    if let Err(e) = status_log_repo.insert_log(
                                        monitor_id,
                                        None,
                                        None,
                                        false,
                                        Some(e.to_string()),
                                    ).await {
                                        error!("Failed to insert error log: {:?}", e);
                                    }

                                    // ALERT LOGIC
                                    let since = OffsetDateTime::now_utc() - TimeDuration::minutes(15);

                                    match alerts_repo.was_recently_sent(monitor_id, "email", since).await {
                                        Ok(false) => {
                                            if let Err(e) = send_alert_email(&url).await {
                                                error!("Failed to send alert email: {:?}", e);
                                            } else {
                                                // Insert alert log
                                                if let Err(e) = alerts_repo.insert_alert(monitor_id, "email", "sendgrid").await {
                                                    error!("Failed to insert alert log: {:?}", e);
                                                }
                                            }
                                        }
                                        Ok(true) => {
                                            info!("Alert already sent recently for monitor_id {}", monitor_id);
                                        }
                                        Err(e) => {
                                            error!("Failed to check recent alerts: {:?}", e);
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

            // Sleep before next ping cycle
            info!("Sleeping before next cycle...");
            sleep(Duration::from_secs(30)).await;
        }
    });
}

// Dummy implementation, zameni kasnije pravim SendGrid pozivom
async fn send_alert_email(url: &str) -> Result<(), reqwest::Error> {
    info!("Sending alert email for down monitor: {}", url);

    // Simulacija API poziva
    // TODO: ovde ide tvoj pravi SendGrid poziv
    Ok(())
}
