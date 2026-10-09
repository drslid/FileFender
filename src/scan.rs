//! Scan pipeline: lists and cache lookup, bounded concurrency, engines in parallel, file
//! policy, one verdict.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use serde::Serialize;
use tokio::sync::Semaphore;

use crate::bazaar::{Bazaar, Reputation};
use crate::clamav::Clamav;
use crate::clamav::client::{self, Reply};
use crate::config::Config;
use crate::hashlist::{HashEntry, HashLists, ListKind};
use crate::metrics::Stats;
use crate::policy::{self, Subject};
use crate::settings::{Settings, SettingsStore};
use crate::util::now_rfc3339;
use crate::yara::Yara;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Serialize)]
pub struct Threat {
    pub engine: &'static str,
    pub name: String,
    pub severity: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineReport {
    /// `ok`, `unavailable` (optional online source unreachable), `disabled`, or `skipped`
    /// when a SHA-256 list decided.
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatures: Option<String>,
}

impl EngineReport {
    fn status(status: &'static str) -> Self {
        EngineReport {
            status,
            version: None,
            signatures: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FileInfo {
    pub name: Option<String>,
    /// Unknown when a hash lookup is answered from the SHA-256 lists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    pub sha256: String,
    #[serde(rename = "type")]
    pub mime: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub verdict: Verdict,
    pub file: FileInfo,
    pub threats: Vec<Threat>,
    pub engines: BTreeMap<&'static str, EngineReport>,
    /// `allowlist` or `blocklist` when the administrator decided for this SHA-256.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listed: Option<&'static str>,
    pub cached: bool,
    pub duration_ms: u64,
    pub scanned_at: String,
}

pub struct Upload {
    pub file: tempfile::NamedTempFile,
    pub size: u64,
    pub sha256: [u8; 32],
    pub name: Option<String>,
    pub mime: Option<String>,
    /// The name sent had right-to-left override characters, removed from `name`.
    pub hidden_name: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("the scanner is starting: {0}")]
    NotReady(String),
    #[error("all scan slots are busy")]
    Busy,
    #[error("{engine} is unavailable: {message}")]
    Unavailable {
        engine: &'static str,
        message: String,
    },
    #[error("{engine} failed: {message}")]
    Failed {
        engine: &'static str,
        message: String,
    },
}

pub struct Scanner {
    cfg: Arc<Config>,
    pub settings: Arc<SettingsStore>,
    pub hashlists: Arc<HashLists>,
    pub clamav: Arc<Clamav>,
    pub yara: Arc<Yara>,
    pub stats: Stats,
    http: reqwest::Client,
    bazaar_endpoint: Option<String>,
    bazaar: ArcSwapOption<Bazaar>,
    permits: Arc<Semaphore>,
    pending: AtomicUsize,
    cache: ArcSwap<VerdictCache>,
}

/// Verdicts by file and signature set; rebuilt when its lifetime setting changes.
struct VerdictCache {
    ttl_minutes: u64,
    entries: moka::sync::Cache<String, Arc<ScanReport>>,
}

impl VerdictCache {
    fn new(ttl_minutes: u64) -> Self {
        VerdictCache {
            ttl_minutes,
            entries: moka::sync::Cache::builder()
                .max_capacity(50_000)
                .time_to_live(Duration::from_secs(ttl_minutes.max(1) * 60))
                .build(),
        }
    }
}

/// A reserved place in the queue, released when the request finishes.
pub struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Scanner {
    pub fn new(
        cfg: Arc<Config>,
        settings: Arc<SettingsStore>,
        hashlists: Arc<HashLists>,
        clamav: Arc<Clamav>,
        yara: Arc<Yara>,
        http: reqwest::Client,
    ) -> Self {
        let ttl = settings.get().limits.cache_ttl_minutes;
        Scanner {
            permits: Arc::new(Semaphore::new(cfg.max_concurrent_scans)),
            pending: AtomicUsize::new(0),
            cache: ArcSwap::from_pointee(VerdictCache::new(ttl)),
            stats: Stats::default(),
            cfg,
            settings,
            hashlists,
            clamav,
            yara,
            http,
            bazaar_endpoint: None,
            bazaar: ArcSwapOption::empty(),
        }
    }

    #[cfg(test)]
    pub fn with_bazaar_endpoint(mut self, endpoint: String) -> Self {
        self.bazaar_endpoint = Some(endpoint);
        self
    }

    /// The MalwareBazaar client for the key saved in the settings, if the lookup is on.
    pub fn bazaar(&self) -> Option<Arc<Bazaar>> {
        let settings = self.settings.get();
        let wanted = &settings.malwarebazaar;
        let key = wanted.auth_key.as_deref().filter(|_| wanted.enabled)?;
        if let Some(current) = self.bazaar.load_full().filter(|b| b.uses_key(key)) {
            return Some(current);
        }
        let client = Arc::new(match &self.bazaar_endpoint {
            Some(endpoint) => {
                Bazaar::with_endpoint(self.http.clone(), key.to_string(), endpoint.clone())
            }
            None => Bazaar::new(self.http.clone(), key.to_string()),
        });
        self.bazaar.store(Some(client.clone()));
        Some(client)
    }

    fn cache(&self) -> Option<Arc<VerdictCache>> {
        let ttl = self.settings.get().limits.cache_ttl_minutes;
        if ttl == 0 {
            return None;
        }
        let current = self.cache.load_full();
        if current.ttl_minutes == ttl {
            return Some(current);
        }
        let fresh = Arc::new(VerdictCache::new(ttl));
        self.cache.store(fresh.clone());
        Some(fresh)
    }

    /// Refuses work early, before the upload is read, when the queue is full.
    pub fn try_reserve(&self) -> Option<Slot<'_>> {
        let max = self.cfg.max_pending_scans;
        self.pending
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max).then_some(n + 1)
            })
            .ok()
            .map(|_| Slot(&self.pending))
    }

    pub fn in_flight(&self) -> (usize, usize) {
        let scanning = self.cfg.max_concurrent_scans - self.permits.available_permits();
        (
            scanning,
            self.pending
                .load(Ordering::Acquire)
                .saturating_sub(scanning),
        )
    }

    /// Why the scanner cannot accept files yet, if it cannot.
    pub fn not_ready_reason(&self) -> Option<String> {
        if !self.clamav.status().usable() {
            let state = self.clamav.state();
            return Some(state.message.unwrap_or_else(|| "ClamAV is starting".into()));
        }
        if self.yara.enabled() && self.yara.rules().is_none() {
            let state = self.yara.state();
            return Some(
                state
                    .message
                    .unwrap_or_else(|| "YARA rules are loading".into()),
            );
        }
        None
    }

    pub fn lookup(&self, sha256: &[u8; 32]) -> Option<ScanReport> {
        if let Some(entry) = self.hashlists.get(sha256) {
            return Some(listed_report(&entry, None, None, None, Instant::now()));
        }
        let settings = self.settings.get();
        let key = self.cache_key(sha256, &settings);
        self.cache()?.entries.get(&key).map(|r| {
            let mut report = (*r).clone();
            report.cached = true;
            report
        })
    }

    /// Verdicts are only reused for the same file, signatures and detection settings.
    fn cache_key(&self, sha256: &[u8; 32], settings: &Settings) -> String {
        let yara = self
            .yara
            .rules()
            .map(|r| format!("{}/{}", r.package, r.release))
            .unwrap_or_default();
        let c = &settings.clamav;
        let options: String = [
            c.alert_encrypted,
            c.alert_macros,
            c.detect_pua,
            c.heuristics,
            c.broken_executables,
            c.phishing,
            settings.malwarebazaar.enabled,
        ]
        .iter()
        .map(|on| if *on { '1' } else { '0' })
        .collect();
        format!(
            "{}|{}|{}|{options}:{}:{}:{}:{}",
            hex::encode(sha256),
            self.clamav.signature_version(),
            yara,
            c.max_recursion,
            c.max_files,
            settings.yara.malicious_score,
            settings.limits.max_file_size,
        )
    }

    pub async fn scan(&self, upload: Upload) -> Result<ScanReport, ScanError> {
        let result = self.scan_inner(upload).await;
        match &result {
            Ok(report) => self.stats.record(report),
            Err(ScanError::Busy) => self.stats.record_rejected(),
            Err(_) => self.stats.record_error(),
        }
        result
    }

    async fn scan_inner(&self, upload: Upload) -> Result<ScanReport, ScanError> {
        let started = Instant::now();
        if let Some(entry) = self.hashlists.get(&upload.sha256) {
            return Ok(listed_report(
                &entry,
                upload.name,
                Some(upload.size),
                upload.mime,
                started,
            ));
        }
        if let Some(reason) = self.not_ready_reason() {
            return Err(ScanError::NotReady(reason));
        }
        let settings = self.settings.get();
        let key = self.cache_key(&upload.sha256, &settings);
        let cache = self.cache();
        let mut report = match cache.as_ref().and_then(|c| c.entries.get(&key)) {
            Some(hit) => {
                let mut report = (*hit).clone();
                report.cached = true;
                report.file.name = upload.name.clone();
                report
            }
            None => {
                let report = self.run_engines(&upload, &settings).await?;
                if let Some(cache) = cache
                    && report
                        .engines
                        .get("malwarebazaar")
                        .is_none_or(|e| e.status != "unavailable")
                {
                    cache.entries.insert(key, Arc::new(report.clone()));
                }
                report
            }
        };

        // The policy depends on the name, which can differ for the same content.
        let subject = Subject {
            name: upload.name.as_deref(),
            mime: upload.mime.as_deref(),
            hidden_name: upload.hidden_name,
        };
        report
            .threats
            .extend(policy::check(&settings.policy, &subject));
        let policy_status = if policy::active(&settings.policy) {
            "ok"
        } else {
            "disabled"
        };
        report
            .engines
            .insert("policy", EngineReport::status(policy_status));
        report
            .threats
            .sort_by_key(|t| std::cmp::Reverse(t.severity));
        report.verdict = verdict_of(&report.threats);
        report.duration_ms = started.elapsed().as_millis() as u64;
        report.scanned_at = now_rfc3339();
        Ok(report)
    }

    async fn run_engines(
        &self,
        upload: &Upload,
        settings: &Settings,
    ) -> Result<ScanReport, ScanError> {
        let scan_timeout = Duration::from_secs(settings.limits.scan_timeout_seconds);
        let permit =
            tokio::time::timeout(self.cfg.queue_timeout, self.permits.clone().acquire_owned())
                .await
                .map_err(|_| ScanError::Busy)?
                .map_err(|_| ScanError::Busy)?;
        // Blocking scans keep the permit until they really end, even if the client leaves.
        let permit = Arc::new(permit);

        let clamav_task = {
            let socket = self.clamav.socket().to_path_buf();
            let file = upload.file.reopen().map_err(|e| ScanError::Failed {
                engine: "clamav",
                message: format!("cannot reopen the upload: {e}"),
            })?;
            let timeout = scan_timeout + Duration::from_secs(15);
            let permit = permit.clone();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                client::scan_fd(&socket, &file, timeout)
            })
        };
        let rules = self.yara.rules();
        let yara_task = rules.clone().map(|rules| {
            let path = upload.file.path().to_path_buf();
            let permit = permit.clone();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                Yara::scan(&rules, &path, scan_timeout)
            })
        });
        drop(permit);
        let bazaar = self.bazaar();
        let sha256 = upload.sha256;
        let bazaar_lookup = async move {
            match bazaar {
                Some(b) => {
                    Some(tokio::time::timeout(Duration::from_secs(4), b.lookup(&sha256)).await)
                }
                None => None,
            }
        };
        let yara_result = async move {
            match yara_task {
                Some(task) => Some(task.await),
                None => None,
            }
        };
        let (clamav_result, yara_result, bazaar_result) =
            tokio::join!(clamav_task, yara_result, bazaar_lookup);

        let mut threats = Vec::new();
        let mut engines = BTreeMap::new();

        let clamav_state = self.clamav.state();
        match clamav_result {
            Ok(Ok(Reply::Clean)) => {}
            Ok(Ok(Reply::Found(name))) => threats.push(Threat {
                engine: "clamav",
                severity: clamav_severity(&name),
                name,
                description: None,
                score: None,
                reference: None,
            }),
            Ok(Ok(Reply::Error(message))) => {
                return Err(ScanError::Failed {
                    engine: "clamav",
                    message,
                });
            }
            Ok(Err(err)) => {
                return Err(ScanError::Unavailable {
                    engine: "clamav",
                    message: format!("{err:#}"),
                });
            }
            Err(join) => {
                return Err(ScanError::Failed {
                    engine: "clamav",
                    message: join.to_string(),
                });
            }
        }
        engines.insert(
            "clamav",
            EngineReport {
                status: "ok",
                version: clamav_state.engine_version.clone(),
                signatures: Some(self.clamav.signature_version()),
            },
        );

        match (yara_result, &rules) {
            (Some(Ok(Ok(matches))), Some(loaded)) => {
                for m in matches {
                    let severity = match m.score {
                        Some(score) if score < settings.yara.malicious_score => Verdict::Suspicious,
                        _ => Verdict::Malicious,
                    };
                    threats.push(Threat {
                        engine: "yara",
                        name: m.rule,
                        severity,
                        description: m.description,
                        score: m.score,
                        reference: m.reference,
                    });
                }
                engines.insert(
                    "yara",
                    EngineReport {
                        status: "ok",
                        version: Some(yara_x::VERSION.to_string()),
                        signatures: Some(format!(
                            "YARA Forge {} {} ({} rules)",
                            loaded.package, loaded.release, loaded.count
                        )),
                    },
                );
            }
            (Some(Ok(Err(err))), _) => {
                return Err(ScanError::Failed {
                    engine: "yara",
                    message: format!("{err:#}"),
                });
            }
            (Some(Err(join)), _) => {
                return Err(ScanError::Failed {
                    engine: "yara",
                    message: join.to_string(),
                });
            }
            _ => {
                engines.insert("yara", EngineReport::status("disabled"));
            }
        }

        let bazaar_status = match bazaar_result {
            Some(Ok(Ok(Reputation::Known { family }))) => {
                threats.push(Threat {
                    engine: "malwarebazaar",
                    name: family.unwrap_or_else(|| "Known malware".into()),
                    severity: Verdict::Malicious,
                    description: Some("SHA-256 listed by MalwareBazaar (abuse.ch)".into()),
                    score: None,
                    reference: Some(format!(
                        "https://bazaar.abuse.ch/sample/{}/",
                        hex::encode(sha256)
                    )),
                });
                "ok"
            }
            Some(Ok(Ok(Reputation::Unknown))) => "ok",
            Some(Ok(Err(err))) => {
                tracing::warn!("MalwareBazaar lookup failed: {err:#}");
                "unavailable"
            }
            Some(Err(_)) => {
                tracing::warn!("MalwareBazaar lookup timed out");
                "unavailable"
            }
            None => "disabled",
        };
        engines.insert("malwarebazaar", EngineReport::status(bazaar_status));

        Ok(ScanReport {
            verdict: verdict_of(&threats),
            file: FileInfo {
                name: upload.name.clone(),
                size: Some(upload.size),
                sha256: hex::encode(upload.sha256),
                mime: upload.mime.clone(),
            },
            threats,
            engines,
            listed: None,
            cached: false,
            duration_ms: 0,
            scanned_at: String::new(),
        })
    }
}

fn verdict_of(threats: &[Threat]) -> Verdict {
    threats
        .iter()
        .map(|t| t.severity)
        .max()
        .unwrap_or(Verdict::Clean)
}

/// The administrator's decision for this SHA-256, without running the engines.
fn listed_report(
    entry: &HashEntry,
    name: Option<String>,
    size: Option<u64>,
    mime: Option<String>,
    started: Instant,
) -> ScanReport {
    let (verdict, listed, threats) = match entry.list {
        ListKind::Allow => (Verdict::Clean, "allowlist", Vec::new()),
        ListKind::Block => (
            Verdict::Malicious,
            "blocklist",
            vec![Threat {
                engine: "blocklist",
                name: "Blocklist.SHA256".into(),
                severity: Verdict::Malicious,
                description: (!entry.note.is_empty()).then(|| entry.note.clone()),
                score: None,
                reference: None,
            }],
        ),
    };
    ScanReport {
        verdict,
        file: FileInfo {
            name,
            size,
            sha256: entry.sha256.clone(),
            mime,
        },
        threats,
        engines: ["clamav", "yara", "malwarebazaar", "policy"]
            .into_iter()
            .map(|engine| (engine, EngineReport::status("skipped")))
            .collect(),
        listed: Some(listed),
        cached: false,
        duration_ms: started.elapsed().as_millis() as u64,
        scanned_at: now_rfc3339(),
    }
}

/// Heuristic and PUA detections are signals, not proof: report them as suspicious, like
/// third-party signatures that flag risky content rather than known malware.
pub fn clamav_severity(name: &str) -> Verdict {
    if name.starts_with("Heuristics.") || name.starts_with("PUA.") {
        Verdict::Suspicious
    } else {
        crate::clamav::feeds::severity(name).unwrap_or(Verdict::Malicious)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heuristics_are_suspicious() {
        assert_eq!(clamav_severity("Win.Test.EICAR_HDB-1"), Verdict::Malicious);
        assert_eq!(
            clamav_severity("Heuristics.Encrypted.Zip"),
            Verdict::Suspicious
        );
        assert_eq!(
            clamav_severity("Heuristics.Limits.Exceeded.MaxScanSize"),
            Verdict::Suspicious
        );
        assert_eq!(clamav_severity("PUA.Win.Tool.Netcat"), Verdict::Suspicious);
        assert_eq!(
            clamav_severity("URLhaus.15711.UNOFFICIAL"),
            Verdict::Suspicious
        );
        assert_eq!(
            clamav_severity("Sanesecurity.Badmacro.Doc.ramf.UNOFFICIAL"),
            Verdict::Malicious
        );
        assert!(Verdict::Malicious > Verdict::Suspicious && Verdict::Suspicious > Verdict::Clean);
    }
}
