//! Audit trail of administrative and security events: `audit.log`, one JSON object per line,
//! readable by the owner only. Security events also go to the webhooks that subscribed.

use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::notify::{Alert, Event, Level, Notifier};

/// Above this size the log moves to `audit.log.1`, replacing the previous one.
const ROTATE_AT: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: String,
    pub action: String,
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

pub struct Audit {
    path: PathBuf,
    write: Mutex<()>,
    notifier: Option<Arc<Notifier>>,
}

/// Actions announced as security alerts, with their title and level.
fn alert_for(action: &str) -> Option<(&'static str, Level)> {
    Some(match action {
        "admin.created" => ("Administrator account created", Level::Warning),
        "admin.reset" => ("All dashboard accounts deleted", Level::Critical),
        "session.signed_in" => ("Dashboard sign-in", Level::Info),
        "account.password_changed" => ("Account password changed", Level::Warning),
        "account.totp_enabled" => ("Two-factor authentication turned on", Level::Info),
        "account.totp_disabled" => ("Two-factor authentication turned off", Level::Critical),
        "account.recovery_code_used" => ("A recovery code was used to sign in", Level::Warning),
        "user.created" => ("Dashboard account created", Level::Warning),
        "user.role_changed" => ("Account role changed", Level::Warning),
        "user.password_reset" => ("Account password reset", Level::Warning),
        "user.totp_reset" => ("Two-factor authentication turned off", Level::Critical),
        "user.deleted" => ("Dashboard account deleted", Level::Warning),
        "key.created" => ("API key created", Level::Info),
        "key.updated" => ("API key restrictions changed", Level::Info),
        "key.revoked" => ("API key revoked", Level::Info),
        "settings.updated" => ("Settings changed", Level::Info),
        "hashlist.added" | "hashlist.removed" => ("SHA-256 list changed", Level::Info),
        "security.throttled" => ("Address blocked after repeated failures", Level::Warning),
        _ => return None,
    })
}

fn rotated(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

impl Audit {
    pub fn new(path: PathBuf, notifier: Option<Arc<Notifier>>) -> Self {
        Audit {
            path,
            write: Mutex::new(()),
            notifier,
        }
    }

    pub fn record(&self, action: &str, actor: &str, ip: Option<IpAddr>, detail: impl Into<String>) {
        let entry = AuditEntry {
            at: crate::util::now_rfc3339(),
            action: action.to_string(),
            actor: actor.to_string(),
            ip: ip.map(|ip| ip.to_string()),
            detail: detail.into(),
        };
        tracing::info!(
            action,
            actor,
            ip = entry.ip.as_deref().unwrap_or("-"),
            detail = entry.detail,
            "audit"
        );
        if let Err(err) = self.append(&entry) {
            tracing::error!("cannot write the audit log: {err:#}");
        }
        if let (Some(notifier), Some((title, level))) = (&self.notifier, alert_for(action)) {
            let mut text = format!("by {}", entry.actor);
            if let Some(ip) = &entry.ip {
                text.push_str(&format!(" from {ip}"));
            }
            if !entry.detail.is_empty() {
                text.push_str(&format!(": {}", entry.detail));
            }
            notifier.send(Alert {
                event: Event::Security,
                level,
                title: title.to_string(),
                text,
                data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }
    }

    fn append(&self, entry: &AuditEntry) -> Result<()> {
        let _guard = self.write.lock().unwrap();
        if std::fs::metadata(&self.path).is_ok_and(|m| m.len() > ROTATE_AT) {
            std::fs::rename(&self.path, rotated(&self.path))?;
        }
        let mut line = serde_json::to_vec(entry)?;
        line.push(b'\n');
        // One write per line with O_APPEND: the CLI and the server can log at the same time.
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)?
            .write_all(&line)?;
        Ok(())
    }

    /// Newest first.
    pub fn recent(&self, limit: usize) -> Vec<AuditEntry> {
        let mut entries = Vec::new();
        for path in [self.path.clone(), rotated(&self.path)] {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            entries.extend(
                text.lines()
                    .rev()
                    .filter_map(|line| serde_json::from_str::<AuditEntry>(line).ok()),
            );
            if entries.len() >= limit {
                break;
            }
        }
        entries.truncate(limit);
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_private_rotated_and_read_newest_first() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let audit = Audit::new(path.clone(), None);
        audit.record(
            "key.created",
            "admin",
            Some("192.0.2.7".parse().unwrap()),
            "ci",
        );
        audit.record("key.revoked", "admin", None, "ci");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let recent = audit.recent(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].action, "key.revoked");
        assert_eq!(recent[1].ip.as_deref(), Some("192.0.2.7"));

        let padding = "x".repeat(4096);
        for _ in 0..600 {
            audit.record("settings.updated", "admin", None, padding.as_str());
        }
        assert!(rotated(&path).is_file());
        assert!(std::fs::metadata(&path).unwrap().len() < ROTATE_AT);
        assert_eq!(audit.recent(1000).len(), 602);
        assert_eq!(audit.recent(5).len(), 5);
    }
}
