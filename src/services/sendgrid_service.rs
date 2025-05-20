use reqwest::Client;
use serde_json::json;
use tracing::{info, error};
use std::fs;

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

    pub async fn send_alert(
        &self,
        to_email: &str,
        subject: &str,
        template_path: &str,
        replacements: &[(&str, &str)],
    ) -> Result<(), String> {
        // Load template file
        let template_content = fs::read_to_string(template_path)
            .map_err(|e| format!("Failed to read template: {:?}", e))?;

        // Replace placeholders
        let mut body = template_content;
        for (key, value) in replacements {
            let placeholder = format!("{{{{{}}}}}", key);
            body = body.replace(&placeholder, value);
        }

        // Build payload
        let payload = json!({
            "personalizations": [{
                "to": [{ "email": to_email }]
            }],
            "from": { "email": self.from_email },
            "subject": subject,
            "content": [{
                "type": "text/html",
                "value": body
            }],
            "tracking_settings": {
                "click_tracking": {
                    "enable": false,
                    "enable_text": false
                }
            }
        });

        // Send request
        let response = self.client
            .post("https://api.sendgrid.com/v3/mail/send")
            .bearer_auth(&self.api_key)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await;

        // Handle response
        match response {
            Ok(res) if res.status().is_success() => {
                info!("Alert email sent to {} with status {}", to_email, res.status());
                Ok(())
            }
            Ok(res) => {
                let status = res.status();
                let text = res.text().await.unwrap_or_else(|_| "No response body".to_string());
                error!("SendGrid API error: {} - {}", status, text);
                Err(format!("SendGrid API error: {} - {}", status, text))
            }
            Err(e) => {
                error!("SendGrid request failed: {:?}", e);
                Err(format!("SendGrid request failed: {:?}", e))
            }
        }
    }

    pub async fn send_raw_html(
        &self,
        to: &str,
        subject: &str,
        html_body: &str,
    ) -> Result<(), reqwest::Error> {
        let payload = json!({
        "personalizations": [{ "to": [{ "email": to }] }],
        "from": { "email": self.from_email },
        "subject": subject,
        "content": [{ "type": "text/html", "value": html_body }]
    });

        let resp = self
            .client
            .post("https://api.sendgrid.com/v3/mail/send")
            .bearer_auth(&self.api_key)
            .json(&payload)
            .send()
            .await?;

        if !resp.status().is_success() {
            tracing::error!("SendGrid error: {:?}", resp.text().await.unwrap_or_default());
        }

        Ok(())
    }

    pub async fn send_password_changed_notification(
        &self,
        to_email: &str,
        user_name: &str,
    ) -> Result<(), String> {
        let subject = "Your Password Has Been Changed";
        let template_path = "src/services/email_templates/email_password_changed.html";

        let replacements = [
            ("user_name", user_name),
            ("support_email", "support@statuspulse.app"),
        ];

        self.send_alert(to_email, subject, template_path, &replacements).await
    }


}
