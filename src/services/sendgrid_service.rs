use reqwest::Client;
use serde_json::json;
use tracing::{info, error};

#[derive(Clone)]
pub struct SendGridService {
    pub api_key: String,
    pub from_email: String,
    pub client: Client,
}

impl SendGridService {
    pub fn new(api_key: String, from_email: String) -> Self {
        Self {
            api_key,
            from_email,
            client: Client::new(),
        }
    }

    pub async fn send_alert(&self, to_email: &str, subject: &str, body: &str) -> Result<(), String> {
        let payload = json!({
            "personalizations": [{
                "to": [{ "email": to_email }]
            }],
            "from": { "email": self.from_email },
            "subject": subject,
            "content": [{
                "type": "text/plain",
                "value": body
            }],
            "tracking_settings": {
                "click_tracking": {
                    "enable": false,
                    "enable_text": false
                }
            }
        });

        let response = self.client
            .post("https://api.sendgrid.com/v3/mail/send")
            .bearer_auth(&self.api_key)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await;

        match response {
            Ok(res) if res.status().is_success() => {
                info!("Alert email sent to {} with status {}", to_email, res.status());
                Ok(())
            }
            Ok(res) => {
                let status = res.status();
                let text = match res.text().await {
                    Ok(t) => t,
                    Err(_) => "No response body".to_string(),
                };
                error!("SendGrid API error: {} - {}", status, text);
                Err(format!("SendGrid API error: {} - {}", status, text))
            }
            Err(e) => {
                error!("SendGrid request failed: {:?}", e);
                Err(format!("SendGrid request failed: {:?}", e))
            }
        }
    }
}
