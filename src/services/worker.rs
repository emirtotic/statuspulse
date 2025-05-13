use crate::{
    db::{monitor_repository::MonitorRepository, status_log_repository::StatusLogRepository, alert_sent_repository::AlertSentRepository},
    services::sendgrid_service::SendGridService,
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

        let monitor_repo = Arc::new(MonitorRepository::new(&state.db));
        let status_log_repo = Arc::new(StatusLogRepository::new(&state.db));
        let alerts_repo = Arc::new(AlertSentRepository::new(&state.db));

        let sendgrid_service = Arc::new(SendGridService::new(
            std::env::var("SENDGRID_API_KEY").expect("SENDGRID_API_KEY must be set"),
            std::env::var("SENDGRID_FROM_EMAIL").expect("SENDGRID_FROM_EMAIL must be set"),
        ));

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

                                    match monitor_repo.get_monitor_owner(monitor_id).await {
                                        Ok(Some(user)) => {
                                            match alerts_repo.was_recently_sent(monitor_id, "email", since).await {
                                                Ok(false) => {
                                                    let subject = format!("Monitor DOWN: {}", monitor.label);
                                                    let body = format!(
                                                        "Dear {},\n\nMonitor [{}] ({}) is DOWN and cannot be reached.\n\nStatusPulse App",
                                                        user.name,
                                                        monitor.label,
                                                        monitor.url
                                                    );

                                                    if let Err(e) = sendgrid_service
                                                        .send_alert(&user.email, &subject, &body)
                                                        .await
                                                    {
                                                        error!("Failed to send alert email: {:?}", e);
                                                    } else {
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
                                        Ok(None) => {
                                            error!("No user found for monitor_id {}", monitor_id);
                                        }
                                        Err(e) => {
                                            error!("Failed to fetch monitor owner: {:?}", e);
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

            info!("Sleeping before next cycle...");
            sleep(Duration::from_secs(900)).await;
        }
    });
}
