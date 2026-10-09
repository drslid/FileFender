//! Webhook alerts: threats found, outdated signatures, engine failures and security events.
//! Only https:// URLs are accepted and redirects are never followed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::scan::Scanner;
use crate::settings::{SettingsStore, Webhook};
use crate::status::EngineStatus;
use crate::util::now_rfc3339;

const SECRET_PREFIX: &str = "ffwh_";

const MAX_ATTEMPTS: u32 = 3;
/// The daily ClamAV database is published several times a day: two days means updates fail.
const STALE_SIGNATURES: Duration = Duration::from_secs(48 * 3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Threats,
    Signatures,
    Engines,
    Security,
}

impl Event {
    pub fn as_str(self) -> &'static str {
        match self {
            Event::Threats => "threats",
            Event::Signatures => "signatures",
            Event::Engines => "engines",
            Event::Security => "security",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warning,
    Critical,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warning => "warning",
            Level::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub event: Event,
    pub level: Level,
    pub title: String,
    pub text: String,
    pub data: Value,
}

pub struct Notifier {
    settings: Arc<SettingsStore>,
    http: reqwest::Client,
    queue: tokio::sync::mpsc::Sender<Alert>,
    recent: moka::sync::Cache<String, ()>,
    service: String,
}

#[derive(Debug)]
pub struct DeliveryError {
    pub message: String,
    retry: bool,
}

fn subscribed(hook: &Webhook, event: Event) -> bool {
    hook.events.iter().any(|e| e == event.as_str())
}

/// A random secret shared with the service that receives a generic webhook.
pub fn new_signing_secret() -> String {
    format!(
        "{SECRET_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(crate::util::random_bytes::<32>())
    )
}

pub fn valid_signing_secret(secret: &str) -> bool {
    secret
        .strip_prefix(SECRET_PREFIX)
        .is_some_and(|rest| rest.len() == 43 && URL_SAFE_NO_PAD.decode(rest).is_ok())
}

/// `t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>">`, like GitHub and Stripe webhooks.
pub fn signature(secret: &str, unix_seconds: u64, body: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC takes keys of any size");
    mac.update(format!("{unix_seconds}.").as_bytes());
    mac.update(body);
    format!(
        "t={unix_seconds},v1={}",
        hex::encode(mac.finalize().into_bytes())
    )
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let mut cut: String = text.chars().take(max.saturating_sub(1)).collect();
        cut.push('…');
        cut
    }
}

/// Slack interprets `<...>` as links and mentions.
fn slack_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// `https://ntfy.sh/alerts` publishes to the topic `alerts` of `https://ntfy.sh/`.
fn ntfy_target(url: &str) -> (String, String) {
    let trimmed = url.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some((base, topic)) if !base.ends_with('/') => (format!("{base}/"), topic.to_string()),
        _ => (url.to_string(), String::new()),
    }
}

/// The request body for a webhook type.
pub fn payload(kind: &str, url: &str, alert: &Alert, service: &str, at: &str) -> (String, Value) {
    let title = truncate(&alert.title, 200);
    let text = truncate(&alert.text, 1800);
    match kind {
        "discord" => (
            url.to_string(),
            json!({
                "username": "FileFender",
                "allowed_mentions": { "parse": [] },
                "embeds": [{
                    "title": title,
                    "description": text,
                    "color": match alert.level {
                        Level::Info => 0x2bb6a3,
                        Level::Warning => 0xf0a020,
                        Level::Critical => 0xe5484d,
                    },
                    "timestamp": at,
                    "footer": { "text": service },
                }],
            }),
        ),
        "slack" => (
            url.to_string(),
            json!({
                "text": format!("*{}*\n{}\n_{}_", slack_escape(&title), slack_escape(&text), slack_escape(service)),
            }),
        ),
        "ntfy" => {
            let (base, topic) = ntfy_target(url);
            (
                base,
                json!({
                    "topic": topic,
                    "title": title,
                    "message": text,
                    "priority": match alert.level {
                        Level::Info => 3,
                        Level::Warning => 4,
                        Level::Critical => 5,
                    },
                    "tags": [match alert.level {
                        Level::Info => "information_source",
                        Level::Warning => "warning",
                        Level::Critical => "rotating_light",
                    }],
                }),
            )
        }
        _ => (
            url.to_string(),
            json!({
                "event": alert.event.as_str(),
                "level": alert.level.as_str(),
                "title": title,
                "text": text,
                "service": service,
                "at": at,
                "data": alert.data,
            }),
        ),
    }
}

impl Notifier {
    /// Starts the delivery worker; must run inside the Tokio runtime.
    pub fn start(
        settings: Arc<SettingsStore>,
        http: reqwest::Client,
        service: String,
    ) -> Arc<Self> {
        let (queue, mut receiver) = tokio::sync::mpsc::channel::<Alert>(256);
        let notifier = Arc::new(Notifier {
            settings,
            http,
            queue,
            recent: moka::sync::Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(3600))
                .build(),
            service,
        });
        let worker = Arc::downgrade(&notifier);
        let slots = Arc::new(tokio::sync::Semaphore::new(4));
        tokio::spawn(async move {
            while let Some(alert) = receiver.recv().await {
                let Some(notifier) = worker.upgrade() else {
                    break;
                };
                let alert = Arc::new(alert);
                let hooks: Vec<Webhook> = notifier
                    .settings
                    .get()
                    .webhooks
                    .iter()
                    .filter(|h| subscribed(h, alert.event))
                    .cloned()
                    .collect();
                for hook in hooks {
                    let Ok(slot) = slots.clone().acquire_owned().await else {
                        return;
                    };
                    let (notifier, alert) = (notifier.clone(), alert.clone());
                    tokio::spawn(async move {
                        let _slot = slot;
                        notifier.deliver_with_retries(&hook, &alert).await;
                    });
                }
            }
        });
        notifier
    }

    pub fn send(&self, alert: Alert) {
        let wanted = self
            .settings
            .get()
            .webhooks
            .iter()
            .any(|h| subscribed(h, alert.event));
        if wanted && self.queue.try_send(alert).is_err() {
            tracing::warn!("too many alerts waiting: one was dropped");
        }
    }

    /// Sends an alert at most once an hour for the same `key`.
    pub fn send_once(&self, key: String, alert: Alert) {
        if self.recent.contains_key(&key) {
            return;
        }
        self.recent.insert(key, ());
        self.send(alert);
    }

    async fn deliver_with_retries(&self, hook: &Webhook, alert: &Alert) {
        let mut delay = Duration::from_secs(2);
        for attempt in 1..=MAX_ATTEMPTS {
            match self.deliver(hook, alert).await {
                Ok(_) => return,
                Err(err) if err.retry && attempt < MAX_ATTEMPTS => {
                    tokio::time::sleep(delay).await;
                    delay *= 5;
                }
                Err(err) => {
                    tracing::warn!(webhook = %hook.id, kind = %hook.kind, "alert not delivered: {}", err.message);
                    return;
                }
            }
        }
    }

    /// One attempt; the error never contains the URL, which often embeds a secret.
    pub async fn deliver(&self, hook: &Webhook, alert: &Alert) -> Result<u16, DeliveryError> {
        let (url, body) = payload(&hook.kind, &hook.url, alert, &self.service, &now_rfc3339());
        // Signed bytes and sent bytes must be the same.
        let body = serde_json::to_vec(&body).unwrap_or_default();
        let mut request = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .timeout(Duration::from_secs(10));
        if hook.kind == "generic" {
            request = request.header("x-filefender-event", alert.event.as_str());
            if let Some(secret) = &hook.secret {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                request = request.header("x-filefender-signature", signature(secret, now, &body));
            }
        }
        let response = request.body(body).send().await.map_err(|e| DeliveryError {
            message: e.without_url().to_string(),
            retry: true,
        })?;
        let status = response.status();
        if status.is_success() {
            Ok(status.as_u16())
        } else {
            Err(DeliveryError {
                message: format!("the webhook answered HTTP {}", status.as_u16()),
                retry: status.is_server_error() || status.as_u16() == 429,
            })
        }
    }

    /// Watches the engines and the signature age, and reports changes.
    pub async fn watch_engines(self: Arc<Self>, scanner: Arc<Scanner>) {
        // Downloads and compilation at first start are not failures.
        tokio::time::sleep(Duration::from_secs(600)).await;
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        let mut last: HashMap<&'static str, EngineStatus> = HashMap::new();
        let mut stale_alert: Option<Instant> = None;
        loop {
            interval.tick().await;
            let clamav = scanner.clamav.state();
            let yara = scanner.yara.state();
            for (engine, status, message) in [
                ("ClamAV", clamav.status, clamav.message.clone()),
                ("YARA", yara.status, yara.message.clone()),
            ] {
                let previous = last.insert(engine, status);
                if status == EngineStatus::Error && previous != Some(EngineStatus::Error) {
                    self.send(Alert {
                        event: Event::Engines,
                        level: Level::Critical,
                        title: format!("{engine} stopped working: scans are refused"),
                        text: message.unwrap_or_default(),
                        data: json!({ "engine": engine, "status": "error" }),
                    });
                } else if previous == Some(EngineStatus::Error) && status.usable() {
                    self.send(Alert {
                        event: Event::Engines,
                        level: Level::Info,
                        title: format!("{engine} works again"),
                        text: String::new(),
                        data: json!({ "engine": engine, "status": "ready" }),
                    });
                }
            }
            let age = clamav.daily_built_at().map(|built| {
                let seconds = (time::OffsetDateTime::now_utc() - built).whole_seconds();
                Duration::from_secs(seconds.max(0) as u64)
            });
            match age {
                Some(age) if age > STALE_SIGNATURES => {
                    if stale_alert.is_none_or(|t| t.elapsed() > Duration::from_secs(24 * 3600)) {
                        stale_alert = Some(Instant::now());
                        self.send(Alert {
                            event: Event::Signatures,
                            level: Level::Warning,
                            title: format!(
                                "ClamAV signatures are {} hours old",
                                age.as_secs() / 3600
                            ),
                            text: clamav
                                .message
                                .clone()
                                .unwrap_or_else(|| "updates keep failing".into()),
                            data: json!({ "engine": "clamav", "age_seconds": age.as_secs() }),
                        });
                    }
                }
                Some(_) if stale_alert.take().is_some() => self.send(Alert {
                    event: Event::Signatures,
                    level: Level::Info,
                    title: "ClamAV signatures are up to date again".into(),
                    text: String::new(),
                    data: json!({ "engine": "clamav" }),
                }),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(title: &str) -> Alert {
        Alert {
            event: Event::Threats,
            level: Level::Critical,
            title: title.into(),
            text: "Win.Test.EICAR_HDB-1 <@everyone>".into(),
            data: json!({ "sha256": "ab" }),
        }
    }

    #[test]
    fn payloads_follow_each_service_format() {
        let a = alert("Malicious file: invoice.exe");
        let at = "2026-10-09T10:00:00Z";
        let (url, discord) = payload(
            "discord",
            "https://discord.com/api/webhooks/1/x",
            &a,
            "scan.example.com",
            at,
        );
        assert_eq!(url, "https://discord.com/api/webhooks/1/x");
        assert_eq!(discord["allowed_mentions"]["parse"], json!([]));
        assert_eq!(discord["embeds"][0]["title"], "Malicious file: invoice.exe");
        assert_eq!(discord["embeds"][0]["color"], 0xe5484d);

        let (_, slack) = payload("slack", "https://hooks.slack.com/services/x", &a, "s", at);
        let text = slack["text"].as_str().unwrap();
        assert!(text.contains("&lt;@everyone&gt;") && !text.contains("<@"));

        let (url, ntfy) = payload("ntfy", "https://ntfy.sh/filefender-alerts", &a, "s", at);
        assert_eq!(url, "https://ntfy.sh/");
        assert_eq!(ntfy["topic"], "filefender-alerts");
        assert_eq!(ntfy["priority"], 5);

        let (_, generic) = payload("generic", "https://example.com/hook", &a, "s", at);
        assert_eq!(generic["event"], "threats");
        assert_eq!(generic["level"], "critical");
        assert_eq!(generic["data"]["sha256"], "ab");

        let long = alert(&"x".repeat(500));
        let (_, body) = payload("generic", "https://example.com", &long, "s", at);
        assert_eq!(body["title"].as_str().unwrap().chars().count(), 200);
    }

    #[test]
    fn ntfy_topics_under_a_path() {
        assert_eq!(
            ntfy_target("https://example.com/ntfy/alerts"),
            (
                "https://example.com/ntfy/".to_string(),
                "alerts".to_string()
            )
        );
    }

    #[test]
    fn signatures_follow_the_documented_format() {
        let secret = new_signing_secret();
        assert!(valid_signing_secret(&secret), "{secret}");
        assert!(!valid_signing_secret("ffwh_short"));
        assert!(!valid_signing_secret(&secret.replace("ffwh_", "other_")));
        // Computed separately with Python's hmac module, like the README examples.
        assert_eq!(
            signature("ffwh_test", 1_791_000_000, b"{\"event\":\"threats\"}"),
            "t=1791000000,v1=e6f0ab3df88d73aa8dba094d9cf88efe77b82757cf270978b1a784871bf313a6"
        );
    }
}
