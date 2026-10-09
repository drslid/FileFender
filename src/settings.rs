//! Detection, update and security settings, edited from the dashboard. The environment only
//! gives the first values: once saved, `settings.json` wins.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{Config, MAX_FILE_SIZE_LIMIT};

pub const POLICY_CATEGORIES: [&str; 6] = [
    "executables",
    "scripts",
    "macros",
    "archives",
    "disk_images",
    "web_pages",
];
pub const WEBHOOK_KINDS: [&str; 4] = ["generic", "discord", "slack", "ntfy"];
pub const WEBHOOK_EVENTS: [&str; 4] = ["threats", "signatures", "engines", "security"];
pub const YARA_PACKAGES: [&str; 3] = ["core", "extended", "full"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    pub clamav: ClamavSettings,
    /// Enabled third-party signature feeds, see [`crate::clamav::feeds`].
    pub feeds: Vec<String>,
    pub yara: YaraSettings,
    pub malwarebazaar: BazaarSettings,
    pub limits: Limits,
    pub policy: Policy,
    pub webhooks: Vec<Webhook>,
    pub dashboard: DashboardAccess,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClamavSettings {
    pub update_interval_hours: u32,
    pub private_mirror: Option<String>,
    pub alert_encrypted: bool,
    pub alert_macros: bool,
    pub detect_pua: bool,
    pub heuristics: bool,
    pub broken_executables: bool,
    pub phishing: bool,
    pub max_recursion: u32,
    pub max_files: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct YaraSettings {
    pub enabled: bool,
    pub package: String,
    pub malicious_score: i64,
    pub update_interval_hours: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BazaarSettings {
    pub enabled: bool,
    pub auth_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    pub max_file_size: u64,
    pub scan_timeout_seconds: u64,
    /// 0 turns the verdict cache off.
    pub cache_ttl_minutes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// File categories refused whatever the engines say, see [`POLICY_CATEGORIES`].
    pub blocked: Vec<String>,
    /// Flags executables named like documents, and double extensions such as `.pdf.exe`.
    pub disguised_files: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Webhook {
    pub id: String,
    pub kind: String,
    pub url: String,
    pub events: Vec<String>,
    /// Signs generic webhooks (`X-FileFender-Signature`); created by the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DashboardAccess {
    /// When not empty, only these networks may open the dashboard (API keys are not affected).
    pub allowed_networks: Vec<String>,
}

impl Settings {
    /// First values, taken from the `FILEFENDER_*` environment variables.
    pub fn from_config(cfg: &Config) -> Self {
        Settings {
            clamav: ClamavSettings {
                update_interval_hours: (cfg.freshclam_interval.as_secs() / 3600).clamp(1, 24)
                    as u32,
                private_mirror: cfg.freshclam_mirror.clone(),
                alert_encrypted: cfg.alert_encrypted,
                alert_macros: cfg.alert_macros,
                detect_pua: cfg.detect_pua,
                heuristics: true,
                broken_executables: true,
                phishing: true,
                max_recursion: 17,
                max_files: 10_000,
            },
            feeds: Vec::new(),
            yara: YaraSettings {
                enabled: cfg.yara_enabled,
                package: cfg.yara_package.clone(),
                malicious_score: cfg.yara_malicious_score,
                update_interval_hours: 24,
            },
            malwarebazaar: BazaarSettings {
                enabled: cfg.abusech_auth_key.is_some(),
                auth_key: cfg.abusech_auth_key.clone(),
            },
            limits: Limits {
                max_file_size: cfg.max_file_size,
                scan_timeout_seconds: cfg.scan_timeout.as_secs().clamp(10, 1800),
                cache_ttl_minutes: (cfg.cache_ttl.as_secs() / 60).min(7 * 24 * 60),
            },
            policy: Policy {
                blocked: Vec::new(),
                disguised_files: true,
            },
            webhooks: Vec::new(),
            dashboard: DashboardAccess {
                allowed_networks: Vec::new(),
            },
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        let c = &self.clamav;
        check(
            (1..=24).contains(&c.update_interval_hours),
            "the ClamAV check interval must be 1 to 24 hours",
        )?;
        if let Some(mirror) = &c.private_mirror {
            // Written into freshclam.conf: one printable token, nothing else.
            check(
                !mirror.is_empty()
                    && mirror.len() <= 512
                    && mirror.chars().all(|c| c.is_ascii_graphic()),
                "the private mirror must be a host name or an http(s):// URL",
            )?;
        }
        check(
            (1..=64).contains(&c.max_recursion),
            "the archive depth must be 1 to 64",
        )?;
        check(
            (100..=1_000_000).contains(&c.max_files),
            "the number of files per archive must be 100 to 1,000,000",
        )?;
        for feed in &self.feeds {
            check(
                crate::clamav::feeds::find(feed).is_some(),
                "unknown signature feed",
            )?;
        }
        let y = &self.yara;
        check(
            YARA_PACKAGES.contains(&y.package.as_str()),
            "the YARA package must be core, extended or full",
        )?;
        check(
            (0..=100).contains(&y.malicious_score),
            "the YARA score must be 0 to 100",
        )?;
        check(
            (6..=168).contains(&y.update_interval_hours),
            "the YARA check interval must be 6 to 168 hours",
        )?;
        if let Some(key) = &self.malwarebazaar.auth_key {
            check(
                (16..=128).contains(&key.len())
                    && key
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "the abuse.ch Auth-Key looks invalid",
            )?;
        }
        check(
            !self.malwarebazaar.enabled || self.malwarebazaar.auth_key.is_some(),
            "MalwareBazaar needs an abuse.ch Auth-Key",
        )?;
        let l = &self.limits;
        check(
            (1024..=MAX_FILE_SIZE_LIMIT).contains(&l.max_file_size),
            "the maximum file size must be 1 KiB to 2 GiB",
        )?;
        check(
            (10..=1800).contains(&l.scan_timeout_seconds),
            "the scan time limit must be 10 to 1800 seconds",
        )?;
        check(
            l.cache_ttl_minutes <= 7 * 24 * 60,
            "the cache can keep verdicts for 7 days at most",
        )?;
        for category in &self.policy.blocked {
            check(
                POLICY_CATEGORIES.contains(&category.as_str()),
                "unknown file category",
            )?;
        }
        check(self.webhooks.len() <= 20, "20 webhooks at most")?;
        for hook in &self.webhooks {
            validate_webhook(hook)?;
            check(
                self.webhooks.iter().filter(|h| h.id == hook.id).count() == 1,
                "two webhooks have the same id",
            )?;
        }
        check(
            self.dashboard.allowed_networks.len() <= 100,
            "100 networks at most",
        )?;
        for network in &self.dashboard.allowed_networks {
            parse_network(network).map_err(|_| format!("invalid network: {network}"))?;
        }
        Ok(())
    }

    pub fn dashboard_allows(&self, ip: IpAddr) -> bool {
        networks_allow(&self.dashboard.allowed_networks, ip)
    }
}

fn check(ok: bool, message: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.to_string()) }
}

pub fn validate_webhook(hook: &Webhook) -> Result<(), String> {
    check(
        !hook.id.is_empty()
            && hook.id.len() <= 32
            && hook
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
        "invalid webhook id",
    )?;
    check(
        WEBHOOK_KINDS.contains(&hook.kind.as_str()),
        "unknown webhook type",
    )?;
    let rest = hook.url.strip_prefix("https://").unwrap_or_default();
    check(
        !rest.is_empty()
            && hook.url.len() <= 2048
            && hook.url.chars().all(|c| c.is_ascii_graphic()),
        "webhooks must use an https:// URL",
    )?;
    check(
        hook.kind != "ntfy" || rest.trim_end_matches('/').contains('/'),
        "the ntfy URL must end with the topic, such as https://ntfy.sh/my-alerts",
    )?;
    check(
        match &hook.secret {
            None => true,
            Some(secret) => hook.kind == "generic" && crate::notify::valid_signing_secret(secret),
        },
        "invalid webhook signing secret",
    )?;
    check(
        !hook.events.is_empty()
            && hook
                .events
                .iter()
                .all(|e| WEBHOOK_EVENTS.contains(&e.as_str())),
        "choose at least one event for each webhook",
    )
}

/// Accepts `192.0.2.7`, `192.0.2.0/24`, `2001:db8::/32`.
pub fn parse_network(text: &str) -> Result<IpNet, ipnet::AddrParseError> {
    let text = text.trim();
    match text.parse::<IpAddr>() {
        Ok(ip) => Ok(IpNet::from(ip)),
        Err(_) => text.parse::<IpNet>().map(|net| net.trunc()),
    }
}

/// An empty list allows everyone.
pub fn networks_allow(networks: &[String], ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    networks.is_empty()
        || networks
            .iter()
            .filter_map(|n| parse_network(n).ok())
            .any(|net| net.contains(&ip))
}

/// Overlays `patch` on `base`, object by object.
fn merge(base: &mut Value, patch: Value) {
    match (base, patch) {
        (Value::Object(base), Value::Object(patch)) => {
            for (key, value) in patch {
                match base.get_mut(&key) {
                    Some(slot) => merge(slot, value),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (slot, value) => *slot = value,
    }
}

type Stamp = Option<(SystemTime, u64)>;

pub struct SettingsStore {
    path: Option<PathBuf>,
    defaults: Settings,
    current: ArcSwap<Settings>,
    stamp: RwLock<Stamp>,
    changes: tokio::sync::watch::Sender<Arc<Settings>>,
    write: Mutex<()>,
}

impl SettingsStore {
    pub fn open(path: &Path, defaults: Settings) -> Result<Self> {
        let store = Self::build(Some(path.to_path_buf()), defaults);
        store.reload()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn in_memory(defaults: Settings) -> Self {
        Self::build(None, defaults)
    }

    fn build(path: Option<PathBuf>, defaults: Settings) -> Self {
        let current = Arc::new(defaults.clone());
        SettingsStore {
            path,
            defaults,
            current: ArcSwap::new(current.clone()),
            stamp: RwLock::new(None),
            changes: tokio::sync::watch::channel(current).0,
            write: Mutex::new(()),
        }
    }

    pub fn get(&self) -> Arc<Settings> {
        self.current.load_full()
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<Arc<Settings>> {
        self.changes.subscribe()
    }

    fn stamp(&self) -> Stamp {
        let meta = std::fs::metadata(self.path.as_ref()?).ok()?;
        Some((meta.modified().ok()?, meta.len()))
    }

    fn read(&self) -> Result<Settings> {
        let mut value = serde_json::to_value(&self.defaults)?;
        if let Some(path) = &self.path {
            match std::fs::read(path) {
                Ok(bytes) => merge(
                    &mut value,
                    serde_json::from_slice(&bytes)
                        .with_context(|| format!("{} is not valid JSON", path.display()))?,
                ),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err).context("cannot read the settings"),
            }
        }
        let settings: Settings =
            serde_json::from_value(value).context("the settings file has invalid values")?;
        settings
            .validate()
            .map_err(|e| anyhow::anyhow!("invalid settings: {e}"))?;
        Ok(settings)
    }

    fn reload(&self) -> Result<()> {
        let stamp = self.stamp();
        let settings = self.read()?;
        *self.stamp.write().unwrap() = stamp;
        self.publish(settings);
        Ok(())
    }

    fn publish(&self, settings: Settings) {
        if *self.get() == settings {
            return;
        }
        let settings = Arc::new(settings);
        self.current.store(settings.clone());
        self.changes.send_replace(settings);
    }

    pub fn save(&self, settings: Settings) -> Result<Arc<Settings>, String> {
        settings.validate()?;
        let _guard = self.write.lock().unwrap();
        if let Some(path) = &self.path {
            crate::util::write_private_json(path, &settings).map_err(|e| {
                tracing::error!("cannot save the settings: {e:#}");
                "cannot save the settings".to_string()
            })?;
            *self.stamp.write().unwrap() = self.stamp();
        }
        self.publish(settings);
        Ok(self.get())
    }

    /// Tests only: applies settings without validation, e.g. an http:// webhook to a mock.
    #[cfg(test)]
    pub fn force(&self, settings: Settings) {
        self.publish(settings);
    }

    /// Applies edits made on disk, for example by `filefender admin unlock-dashboard`.
    pub async fn watch(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        loop {
            interval.tick().await;
            if self.stamp() != *self.stamp.read().unwrap()
                && let Err(err) = self.reload()
            {
                tracing::error!("ignoring the edited settings: {err:#}");
                *self.stamp.write().unwrap() = self.stamp();
            }
        }
    }
}

/// Edits `settings.json` from the command line, keeping every other value.
pub fn edit_file(
    path: &Path,
    defaults: Settings,
    change: impl FnOnce(&mut Settings),
) -> Result<()> {
    let store = SettingsStore::open(path, defaults)?;
    let mut settings = (*store.get()).clone();
    change(&mut settings);
    store
        .save(settings)
        .map_err(|e| anyhow::anyhow!(e))
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> Settings {
        Settings::from_config(&Config::from_lookup(|_| None).unwrap())
    }

    #[test]
    fn saved_settings_override_the_environment() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let store = SettingsStore::open(&path, defaults()).unwrap();
        assert_eq!(store.get().yara.package, "core");
        let mut changed = (*store.get()).clone();
        changed.yara.package = "extended".into();
        changed.feeds = vec!["urlhaus".into()];
        store.save(changed).unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&path).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);

        let mut env_defaults = defaults();
        env_defaults.yara.package = "full".into();
        let reopened = SettingsStore::open(&path, env_defaults).unwrap();
        assert_eq!(
            reopened.get().yara.package,
            "extended",
            "the dashboard wins"
        );
        assert_eq!(reopened.get().feeds, ["urlhaus"]);
    }

    #[test]
    fn partial_files_keep_the_other_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{"clamav": {"detect_pua": true}}"#).unwrap();
        let store = SettingsStore::open(&path, defaults()).unwrap();
        assert!(store.get().clamav.detect_pua);
        assert_eq!(store.get().clamav.max_recursion, 17);
    }

    #[test]
    fn invalid_values_are_refused() {
        let store = SettingsStore::in_memory(defaults());
        let mut bad = defaults();
        bad.clamav.update_interval_hours = 0;
        assert!(store.save(bad).is_err());
        let mut bad = defaults();
        bad.webhooks.push(Webhook {
            id: "wh_1".into(),
            kind: "discord".into(),
            url: "http://insecure.example".into(),
            events: vec!["threats".into()],
            secret: None,
        });
        assert!(store.save(bad).is_err());
        let mut bad = defaults();
        bad.malwarebazaar.enabled = true;
        bad.malwarebazaar.auth_key = None;
        assert!(store.save(bad).is_err());
        let mut bad = defaults();
        bad.dashboard.allowed_networks = vec!["10.0.0.0/33".into()];
        assert!(store.save(bad).is_err());
        let mut bad = defaults();
        bad.clamav.private_mirror = Some("mirror.example\nDatabaseCustomURL http://x".into());
        assert!(
            store.save(bad).is_err(),
            "no line injection in freshclam.conf"
        );
        let mut bad = defaults();
        bad.webhooks.push(Webhook {
            id: "wh_2".into(),
            kind: "ntfy".into(),
            url: "https://ntfy.sh/".into(),
            events: vec!["threats".into()],
            secret: None,
        });
        assert!(store.save(bad).is_err(), "ntfy needs a topic");
        let mut bad = defaults();
        bad.webhooks.push(Webhook {
            id: "wh_3".into(),
            kind: "slack".into(),
            url: "https://hooks.slack.com/services/x".into(),
            events: vec!["threats".into()],
            secret: Some(crate::notify::new_signing_secret()),
        });
        assert!(store.save(bad).is_err(), "only generic webhooks are signed");
    }

    #[test]
    fn network_allowlists() {
        let networks = vec!["192.0.2.0/24".to_string(), "2001:db8::1".to_string()];
        assert!(networks_allow(&networks, "192.0.2.77".parse().unwrap()));
        assert!(networks_allow(
            &networks,
            "::ffff:192.0.2.77".parse().unwrap()
        ));
        assert!(networks_allow(&networks, "2001:db8::1".parse().unwrap()));
        assert!(!networks_allow(&networks, "198.51.100.1".parse().unwrap()));
        assert!(networks_allow(&[], "198.51.100.1".parse().unwrap()));
    }
}
