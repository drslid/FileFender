use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const KEY_PREFIX: &str = "ff_";
const MAX_KEY_NETWORKS: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    pub id: String,
    pub label: String,
    /// SHA-256 of the full key, hex encoded. The key itself is never stored.
    pub sha256: String,
    pub created_at: String,
    /// When not empty, the key only works from these addresses and networks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_networks: Vec<String>,
    /// Requests per minute; no limit when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_per_minute: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl StoredKey {
    pub fn expired(&self) -> bool {
        self.expires_at
            .as_deref()
            .and_then(|t| OffsetDateTime::parse(t, &Rfc3339).ok())
            .is_some_and(|t| t <= OffsetDateTime::now_utc())
    }
}

/// What the administrator may restrict on a key.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Restrictions {
    #[serde(default)]
    pub allowed_networks: Vec<String>,
    #[serde(default)]
    pub rate_per_minute: Option<u32>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

impl Restrictions {
    /// Checks and normalizes the values (networks trimmed, expiry in UTC).
    pub fn validate(mut self) -> Result<Self, String> {
        if self.allowed_networks.len() > MAX_KEY_NETWORKS {
            return Err(format!("{MAX_KEY_NETWORKS} networks at most"));
        }
        for network in &mut self.allowed_networks {
            *network = network.trim().to_string();
            crate::settings::parse_network(network)
                .map_err(|_| format!("invalid network: {network}"))?;
        }
        self.allowed_networks.retain(|n| !n.is_empty());
        if self
            .rate_per_minute
            .is_some_and(|r| !(1..=100_000).contains(&r))
        {
            return Err("the limit must be 1 to 100,000 requests per minute".into());
        }
        if let Some(expiry) = &self.expires_at {
            let at = OffsetDateTime::parse(expiry.trim(), &Rfc3339)
                .map_err(|_| "the expiry date is invalid".to_string())?;
            self.expires_at = Some(crate::util::rfc3339(at.to_offset(time::UtcOffset::UTC)));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Usage {
    pub last_used_at: Option<String>,
    pub last_ip: Option<String>,
    pub requests: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct KeyFile {
    keys: Vec<StoredKey>,
}

/// API keys, loaded from `keys.json` and reloaded when the CLI changes the file. Usage
/// counters are kept in `key-usage.json`, written once a minute.
pub struct KeyStore {
    path: PathBuf,
    by_hash: RwLock<HashMap<[u8; 32], Arc<StoredKey>>>,
    modified: RwLock<Option<SystemTime>>,
    usage_path: PathBuf,
    usage: Mutex<HashMap<String, Usage>>,
    usage_dirty: AtomicBool,
    /// Current minute and requests counted in it, per key.
    windows: Mutex<HashMap<String, (u64, u32)>>,
}

impl KeyStore {
    pub fn open(path: &Path) -> Result<Self> {
        let usage_path = path.with_file_name("key-usage.json");
        let usage = std::fs::read(&usage_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let store = KeyStore {
            path: path.to_path_buf(),
            by_hash: RwLock::new(HashMap::new()),
            modified: RwLock::new(None),
            usage_path,
            usage: Mutex::new(usage),
            usage_dirty: AtomicBool::new(false),
            windows: Mutex::new(HashMap::new()),
        };
        store.reload()?;
        Ok(store)
    }

    pub fn count(&self) -> usize {
        self.by_hash.read().unwrap().len()
    }

    pub fn verify(&self, presented: &str) -> Option<Arc<StoredKey>> {
        if !presented.starts_with(KEY_PREFIX) || presented.len() > 128 {
            return None;
        }
        let digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        if let Some(key) = self.lookup(&digest) {
            return Some(key);
        }
        // A key created a moment ago with `filefender keys create` works on its first request.
        self.reload_if_changed();
        self.lookup(&digest)
    }

    fn lookup(&self, digest: &[u8; 32]) -> Option<Arc<StoredKey>> {
        self.by_hash.read().unwrap().get(digest).cloned()
    }

    pub fn reload_if_changed(&self) {
        let current = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        if current != *self.modified.read().unwrap() {
            match self.reload() {
                Ok(()) => tracing::info!(keys = self.count(), "API keys reloaded"),
                Err(err) => tracing::error!("cannot reload API keys: {err:#}"),
            }
        }
    }

    fn reload(&self) -> Result<()> {
        let modified = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        let file = read_file(&self.path)?;
        let mut map = HashMap::new();
        for key in file.keys {
            let mut digest = [0u8; 32];
            if hex::decode_to_slice(&key.sha256, &mut digest).is_err() {
                tracing::warn!(id = %key.id, "ignoring API key with an invalid hash in keys.json");
                continue;
            }
            map.insert(digest, Arc::new(key));
        }
        *self.by_hash.write().unwrap() = map;
        *self.modified.write().unwrap() = modified;
        Ok(())
    }

    /// Picks up keys created or revoked with `filefender keys ...` while the server runs.
    pub async fn watch(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        let mut ticks = 0u32;
        loop {
            interval.tick().await;
            self.reload_if_changed();
            ticks += 1;
            if ticks.is_multiple_of(20) {
                self.flush_usage();
            }
        }
    }

    /// Counts a request; returns how many seconds to wait when the key is over its limit.
    pub fn allow_request(&self, key: &StoredKey) -> Result<(), u64> {
        let Some(limit) = key.rate_per_minute else {
            return Ok(());
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let minute = now / 60;
        let mut windows = self.windows.lock().unwrap();
        let window = windows.entry(key.id.clone()).or_insert((minute, 0));
        if window.0 != minute {
            *window = (minute, 0);
        }
        if window.1 >= limit {
            return Err(60 - now % 60);
        }
        window.1 += 1;
        Ok(())
    }

    pub fn touch(&self, key: &StoredKey, ip: IpAddr) {
        let mut usage = self.usage.lock().unwrap();
        let entry = usage.entry(key.id.clone()).or_default();
        entry.requests += 1;
        entry.last_used_at = Some(crate::util::now_rfc3339());
        entry.last_ip = Some(ip.to_string());
        self.usage_dirty.store(true, Ordering::Relaxed);
    }

    pub fn usage(&self, id: &str) -> Usage {
        self.usage
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .unwrap_or_default()
    }

    /// Saves the usage counters, forgetting revoked keys.
    pub fn flush_usage(&self) {
        if !self.usage_dirty.swap(false, Ordering::Relaxed) {
            return;
        }
        let known: Vec<String> = self
            .by_hash
            .read()
            .unwrap()
            .values()
            .map(|k| k.id.clone())
            .collect();
        let snapshot = {
            let mut usage = self.usage.lock().unwrap();
            usage.retain(|id, _| known.contains(id));
            usage.clone()
        };
        if let Err(err) = crate::util::write_private_json(&self.usage_path, &snapshot) {
            tracing::warn!("cannot save the API key usage: {err:#}");
        }
    }
}

fn read_file(path: &Path) -> Result<KeyFile> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("{} is not a valid key file", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(KeyFile::default()),
        Err(err) => Err(err).with_context(|| format!("cannot read {}", path.display())),
    }
}

fn write_file(path: &Path, file: &KeyFile) -> Result<()> {
    crate::util::write_private_json(path, file)
}

pub fn generate_key() -> String {
    let bytes: [u8; 32] = crate::util::random_bytes();
    format!("{KEY_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub fn create(path: &Path, label: &str) -> Result<(StoredKey, String)> {
    let label = label.trim();
    if label.is_empty() || label.len() > 64 || label.chars().any(char::is_control) {
        bail!("the label must be 1 to 64 printable characters");
    }
    let mut file = read_file(path)?;
    if file.keys.iter().any(|k| k.label == label) {
        bail!("a key labelled {label:?} already exists");
    }
    let secret = generate_key();
    let id_bytes: [u8; 4] = crate::util::random_bytes();
    let key = StoredKey {
        id: format!("key_{}", hex::encode(id_bytes)),
        label: label.to_string(),
        sha256: hex::encode(Sha256::digest(secret.as_bytes())),
        created_at: crate::util::now_rfc3339(),
        allowed_networks: Vec::new(),
        rate_per_minute: None,
        expires_at: None,
    };
    file.keys.push(key.clone());
    write_file(path, &file)?;
    Ok((key, secret))
}

/// Replaces the restrictions of a key; `None` when there is no such key.
pub fn restrict(path: &Path, id: &str, restrictions: Restrictions) -> Result<Option<StoredKey>> {
    let mut file = read_file(path)?;
    let Some(key) = file.keys.iter_mut().find(|k| k.id == id) else {
        return Ok(None);
    };
    key.allowed_networks = restrictions.allowed_networks;
    key.rate_per_minute = restrictions.rate_per_minute;
    key.expires_at = restrictions.expires_at;
    let key = key.clone();
    write_file(path, &file)?;
    Ok(Some(key))
}

pub fn list(path: &Path) -> Result<Vec<StoredKey>> {
    Ok(read_file(path)?.keys)
}

pub fn revoke(path: &Path, id_or_label: &str) -> Result<StoredKey> {
    let mut file = read_file(path)?;
    let position = file
        .keys
        .iter()
        .position(|k| k.id == id_or_label || k.label == id_or_label)
        .with_context(|| format!("no key with id or label {id_or_label:?}"))?;
    let removed = file.keys.remove(position);
    write_file(path, &file)?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_verify_revoke_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let (key, secret) = create(&path, "ci").unwrap();
        assert!(secret.starts_with(KEY_PREFIX) && secret.len() == 46);
        assert!(!std::fs::read_to_string(&path).unwrap().contains(&secret));

        let store = KeyStore::open(&path).unwrap();
        assert_eq!(store.verify(&secret).unwrap().id, key.id);
        assert!(store.verify("ff_wrong").is_none());
        assert!(store.verify(&secret[3..]).is_none());

        assert!(create(&path, "ci").is_err(), "labels are unique");
        revoke(&path, "ci").unwrap();
        let store = KeyStore::open(&path).unwrap();
        assert!(store.verify(&secret).is_none());
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn key_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        create(&path, "app").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn new_key_works_immediately_on_a_running_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let store = KeyStore::open(&path).unwrap();
        let (key, secret) = create(&path, "fresh").unwrap();
        assert_eq!(store.verify(&secret).unwrap().id, key.id);
    }

    #[test]
    fn missing_file_means_no_keys() {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::open(&dir.path().join("keys.json")).unwrap();
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn restrictions_are_validated_and_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let (key, secret) = create(&path, "ci").unwrap();

        let bad = |r: Restrictions| r.validate().is_err();
        assert!(bad(Restrictions {
            allowed_networks: vec!["10.0.0.0/33".into()],
            ..Default::default()
        }));
        assert!(bad(Restrictions {
            rate_per_minute: Some(0),
            ..Default::default()
        }));
        assert!(bad(Restrictions {
            expires_at: Some("tomorrow".into()),
            ..Default::default()
        }));
        let ok = Restrictions {
            allowed_networks: vec![" 192.0.2.0/24 ".into()],
            rate_per_minute: Some(2),
            expires_at: Some("2999-12-31T23:59:59+01:00".into()),
        }
        .validate()
        .unwrap();
        assert_eq!(ok.allowed_networks, ["192.0.2.0/24"]);
        assert_eq!(ok.expires_at.as_deref(), Some("2999-12-31T22:59:59Z"));
        assert!(
            restrict(&path, "key_missing", ok.clone())
                .unwrap()
                .is_none()
        );
        restrict(&path, &key.id, ok).unwrap().unwrap();

        let store = KeyStore::open(&path).unwrap();
        let stored = store.verify(&secret).unwrap();
        assert!(!stored.expired());
        assert!(store.allow_request(&stored).is_ok());
        assert!(store.allow_request(&stored).is_ok());
        let wait = store.allow_request(&stored).unwrap_err();
        assert!((1..=60).contains(&wait));

        store.touch(&stored, "192.0.2.9".parse().unwrap());
        store.flush_usage();
        let reopened = KeyStore::open(&path).unwrap();
        let usage = reopened.usage(&key.id);
        assert_eq!(usage.requests, 1);
        assert_eq!(usage.last_ip.as_deref(), Some("192.0.2.9"));

        let past = StoredKey {
            expires_at: Some("2020-01-01T00:00:00Z".into()),
            ..(*stored).clone()
        };
        assert!(past.expired());
    }
}
