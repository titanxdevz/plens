use crate::error::{PlensError, Result};
use crate::model::Severity;
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertPayload {
    pub target: String,
    pub scan_id: String,
    pub title: String,
    pub summary: String,
    pub severity: Severity,
    pub risk_score: u32,
    pub risk_grade: String,
    pub score_delta: Option<i32>,
    pub changes: Vec<String>,
}

pub struct AlertManager {
    client: Client,
    last_sent: Mutex<HashMap<String, Instant>>,
}

impl Default for AlertManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertManager {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            last_sent: Mutex::new(HashMap::new()),
        }
    }

    pub fn should_suppress(&self, key: &str, cooldown: Duration) -> bool {
        let mut map = self.last_sent.lock().unwrap();
        if let Some(last) = map.get(key) {
            if last.elapsed() < cooldown {
                return true;
            }
        }
        map.insert(key.to_string(), Instant::now());
        false
    }

    pub async fn dispatch_alert(
        &self,
        discord_url: Option<&str>,
        generic_url: Option<&str>,
        alert: &AlertPayload,
    ) -> Result<()> {
        let dedup_key = format!("{}:{}", alert.target, alert.title);
        if self.should_suppress(&dedup_key, Duration::from_secs(300)) {
            return Ok(());
        }

        if let Some(url) = discord_url {
            let _ = self.send_discord(url, alert).await;
        }

        if let Some(url) = generic_url {
            let _ = self.send_generic(url, alert).await;
        }

        Ok(())
    }

    pub async fn send_discord(&self, url: &str, alert: &AlertPayload) -> Result<()> {
        let color = match alert.severity {
            Severity::Critical => 0xEF4444,
            Severity::High => 0xF97316,
            Severity::Medium => 0xEAB308,
            Severity::Low => 0x06B6D4,
            Severity::Info => 0x3B82F6,
        };

        let mut fields = vec![
            json!({
                "name": "Target",
                "value": alert.target,
                "inline": true
            }),
            json!({
                "name": "Risk Posture",
                "value": format!("Grade {} ({}/100)", alert.risk_grade, alert.risk_score),
                "inline": true
            }),
        ];

        if let Some(delta) = alert.score_delta {
            fields.push(json!({
                "name": "Score Delta",
                "value": format!("{:+}", delta),
                "inline": true
            }));
        }

        if !alert.changes.is_empty() {
            fields.push(json!({
                "name": "Detected Changes",
                "value": alert.changes.join("\n"),
                "inline": false
            }));
        }

        let body = json!({
            "embeds": [{
                "title": format!("🚨 PortLens Alert: {}", alert.title),
                "description": alert.summary,
                "color": color,
                "fields": fields,
                "footer": {
                    "text": format!("Scan ID: {} • {}", alert.scan_id, Utc::now().format("%Y-%m-%d %H:%M:%S UTC"))
                }
            }]
        });

        self.post_json_with_retry(url, &body, "Discord").await
    }

    pub async fn send_generic(&self, url: &str, alert: &AlertPayload) -> Result<()> {
        let body = serde_json::to_value(alert).unwrap_or_default();
        self.post_json_with_retry(url, &body, "Generic").await
    }

    /// Post JSON payload with exponential backoff and jitter (B.6)
    async fn post_json_with_retry(&self, url: &str, body: &serde_json::Value, name: &str) -> Result<()> {
        let mut backoff = Duration::from_millis(500);
        let max_attempts = 3;

        for attempt in 1..=max_attempts {
            let res = self.client.post(url).json(body).send().await;
            match res {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    if attempt == max_attempts {
                        return Err(PlensError::Network {
                            message: format!("{name} webhook responded with HTTP {}", resp.status()),
                        });
                    }
                }
                Err(e) => {
                    if attempt == max_attempts {
                        return Err(PlensError::Network {
                            message: format!("{name} alert dispatch failed: {e}"),
                        });
                    }
                }
            }

            // Pseudo-random jitter based on subsecond millis
            let jitter_ms = (Utc::now().timestamp_subsec_millis() % 200) as u64;
            tokio::time::sleep(backoff + Duration::from_millis(jitter_ms)).await;
            backoff = (backoff * 2).min(Duration::from_secs(5));
        }

        Ok(())
    }
}
