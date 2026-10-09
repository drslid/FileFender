//! YARA-X engine fed with the YARA Forge rule packages, compiled in the background
//! and swapped atomically so scans never wait for an update.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwapOption;
use serde::Serialize;

use crate::config::Config;
use crate::settings::{SettingsStore, YaraSettings};
use crate::status::EngineStatus;
use crate::util::now_rfc3339;

const RELEASES: &str = "https://github.com/YARAHQ/yara-forge/releases";
const MAX_RULES_SIZE: u64 = 256 * 1024 * 1024;

pub struct LoadedRules {
    pub rules: yara_x::Rules,
    pub package: String,
    pub release: String,
    pub count: usize,
    pub loaded_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct YaraState {
    pub status: EngineStatus,
    pub message: Option<String>,
    pub package: String,
    pub release: Option<String>,
    pub rules: usize,
    pub loaded_at: Option<String>,
    pub last_check: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct YaraMatch {
    pub rule: String,
    pub score: Option<i64>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub reference: Option<String>,
}

pub struct Yara {
    cfg: Arc<Config>,
    settings: Arc<SettingsStore>,
    http: reqwest::Client,
    loaded: ArcSwapOption<LoadedRules>,
    state: RwLock<YaraState>,
    update_now: tokio::sync::Notify,
}

impl Yara {
    pub fn new(cfg: Arc<Config>, settings: Arc<SettingsStore>, http: reqwest::Client) -> Self {
        let yara = settings.get().yara.clone();
        let status = if yara.enabled {
            EngineStatus::Starting
        } else {
            EngineStatus::Disabled
        };
        Yara {
            cfg,
            settings,
            http,
            loaded: ArcSwapOption::empty(),
            update_now: tokio::sync::Notify::new(),
            state: RwLock::new(YaraState {
                status,
                message: None,
                package: yara.package,
                release: None,
                rules: 0,
                loaded_at: None,
                last_check: None,
            }),
        }
    }

    pub fn enabled(&self) -> bool {
        self.settings.get().yara.enabled
    }

    /// The rules to scan with, unless YARA is off.
    pub fn rules(&self) -> Option<Arc<LoadedRules>> {
        self.enabled().then(|| self.loaded.load_full()).flatten()
    }

    pub fn state(&self) -> YaraState {
        self.state.read().unwrap().clone()
    }

    /// Checks for a new rules release now instead of waiting for the next day.
    pub fn request_update(&self) {
        self.update_now.notify_one();
    }

    fn set_status(&self, status: EngineStatus, message: Option<String>) {
        let mut state = self.state.write().unwrap();
        state.status = status;
        state.message = message;
    }

    fn install(&self, loaded: LoadedRules) {
        {
            let mut state = self.state.write().unwrap();
            state.status = EngineStatus::Ready;
            state.message = None;
            state.package = loaded.package.clone();
            state.release = Some(loaded.release.clone());
            state.rules = loaded.count;
            state.loaded_at = Some(loaded.loaded_at.clone());
        }
        tracing::info!(
            package = loaded.package,
            release = loaded.release,
            rules = loaded.count,
            "YARA rules active"
        );
        self.loaded.store(Some(Arc::new(loaded)));
    }

    #[cfg(test)]
    pub fn install_source(&self, release: &str, source: &str) -> Result<()> {
        let (rules, count) = compile(source)?;
        self.install(LoadedRules {
            rules,
            package: self.settings.get().yara.package.clone(),
            release: release.into(),
            count,
            loaded_at: now_rfc3339(),
        });
        Ok(())
    }

    fn dir(&self) -> PathBuf {
        self.cfg.data_dir.join("yara")
    }

    pub async fn run(self: Arc<Self>) {
        if let Err(err) = std::fs::create_dir_all(self.dir()) {
            self.set_status(
                EngineStatus::Error,
                Some(format!("cannot create the rules directory: {err}")),
            );
            return;
        }
        let mut changes = self.settings.subscribe();
        let mut retry = Duration::from_secs(60);
        loop {
            let wanted = self.settings.get().yara.clone();
            if !wanted.enabled {
                self.loaded.store(None);
                {
                    let mut state = self.state.write().unwrap();
                    *state = YaraState {
                        status: EngineStatus::Disabled,
                        message: None,
                        package: wanted.package.clone(),
                        release: None,
                        rules: 0,
                        loaded_at: None,
                        last_check: state.last_check.clone(),
                    };
                }
                if !yara_settings_change(&mut changes, &wanted).await {
                    return;
                }
                continue;
            }
            if self
                .loaded
                .load()
                .as_ref()
                .is_none_or(|r| r.package != wanted.package)
            {
                self.loaded.store(None);
                self.set_status(EngineStatus::Starting, None);
                self.state.write().unwrap().package = wanted.package.clone();
                match self.load_cached(&wanted.package).await {
                    Ok(Some(loaded)) => self.install(loaded),
                    Ok(None) => {}
                    Err(err) => tracing::warn!("ignoring cached YARA rules: {err:#}"),
                }
            }
            let wait = match self.update(&wanted.package).await {
                Ok(_) => {
                    retry = Duration::from_secs(60);
                    Duration::from_secs(u64::from(wanted.update_interval_hours) * 3600)
                }
                Err(err) => {
                    tracing::warn!("YARA rules update failed: {err:#}");
                    if self.loaded.load().is_none() {
                        self.set_status(EngineStatus::Error, Some(format!("{err:#}")));
                    } else {
                        self.state.write().unwrap().message =
                            Some(format!("last update failed: {err:#}"));
                    }
                    let wait = retry;
                    retry = (retry * 2).min(Duration::from_secs(6 * 3600));
                    wait
                }
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = self.update_now.notified() => {}
                alive = yara_settings_change(&mut changes, &wanted) => if !alive { return },
            }
        }
    }

    fn cache_paths(&self, package: &str) -> (PathBuf, PathBuf) {
        let base = format!("{package}-yarax{}", yara_x::VERSION);
        (
            self.dir().join(format!("{base}.rules")),
            self.dir().join(format!("{base}.release")),
        )
    }

    async fn load_cached(&self, package: &str) -> Result<Option<LoadedRules>> {
        let (rules_path, release_path) = self.cache_paths(package);
        if !rules_path.is_file() || !release_path.is_file() {
            return Ok(None);
        }
        let release = std::fs::read_to_string(&release_path)?.trim().to_string();
        let started = Instant::now();
        let rules = tokio::task::spawn_blocking(move || -> Result<yara_x::Rules> {
            let bytes = std::fs::read(&rules_path)?;
            Ok(yara_x::Rules::deserialize(&bytes)?)
        })
        .await??;
        let count = rules.iter().count();
        tracing::info!(
            release,
            rules = count,
            ms = started.elapsed().as_millis() as u64,
            "cached YARA rules loaded"
        );
        Ok(Some(LoadedRules {
            rules,
            package: package.to_string(),
            release,
            count,
            loaded_at: now_rfc3339(),
        }))
    }

    async fn update(&self, package: &str) -> Result<bool> {
        let release = match &self.cfg.yara_rules_url {
            Some(url) => {
                use sha2::Digest;
                format!(
                    "custom-{}",
                    &hex::encode(sha2::Sha256::digest(url.as_bytes()))[..8]
                )
            }
            None => self.latest_release().await?,
        };
        self.state.write().unwrap().last_check = Some(now_rfc3339());
        let current = self.loaded.load_full();
        if current
            .as_ref()
            .is_some_and(|r| r.release == release && r.package == package)
        {
            return Ok(false);
        }
        if current.is_none() {
            self.set_status(
                EngineStatus::Downloading,
                Some(format!("downloading YARA Forge {release} ({package})")),
            );
        }
        let source = self.download(&release, package).await?;
        if current.is_none() {
            self.set_status(EngineStatus::Loading, Some("compiling YARA rules".into()));
        }
        let started = Instant::now();
        let (rules, count) = tokio::task::spawn_blocking(move || compile(&source)).await??;
        tracing::info!(
            release,
            package,
            rules = count,
            seconds = started.elapsed().as_secs(),
            "YARA rules compiled"
        );

        let (rules_path, release_path) = self.cache_paths(package);
        match rules.serialize() {
            Ok(bytes) => {
                if let Err(err) = write_atomic(&rules_path, &bytes)
                    .and_then(|_| write_atomic(&release_path, release.as_bytes()))
                {
                    tracing::warn!("cannot cache compiled YARA rules: {err:#}");
                }
            }
            Err(err) => tracing::warn!("cannot serialize YARA rules: {err}"),
        }
        if self.settings.get().yara.package != package {
            // The package changed while compiling; the run loop starts over.
            return Ok(false);
        }
        self.install(LoadedRules {
            rules,
            package: package.to_string(),
            release,
            count,
            loaded_at: now_rfc3339(),
        });
        Ok(true)
    }

    /// The latest tag, read from the redirect of `/releases/latest` (no API quota).
    async fn latest_release(&self) -> Result<String> {
        let response = self
            .http
            .head(format!("{RELEASES}/latest"))
            .send()
            .await
            .map_err(|e| e.without_url())?;
        let tag = response
            .url()
            .path_segments()
            .and_then(|mut s| s.next_back().map(str::to_string))
            .filter(|t| {
                !t.is_empty()
                    && t.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            })
            .context("cannot determine the latest YARA Forge release")?;
        if tag == "latest" {
            bail!("cannot determine the latest YARA Forge release");
        }
        Ok(tag)
    }

    async fn download(&self, release: &str, package: &str) -> Result<String> {
        let url = match &self.cfg.yara_rules_url {
            Some(url) => url.clone(),
            None => format!("{RELEASES}/download/{release}/yara-forge-rules-{package}.zip"),
        };
        let response = self
            .http
            .get(&url)
            .timeout(Duration::from_secs(300))
            .send()
            .await
            .map_err(|e| e.without_url())?
            .error_for_status()
            .map_err(|e| e.without_url())?;
        if response
            .content_length()
            .is_some_and(|len| len > MAX_RULES_SIZE)
        {
            bail!("the rules package is too large");
        }
        let bytes = response.bytes().await.map_err(|e| e.without_url())?;
        let package = package.to_string();
        tokio::task::spawn_blocking(move || extract_rules(&bytes, &package)).await?
    }

    /// Scans a file; blocking, call it from `spawn_blocking`.
    pub fn scan(loaded: &LoadedRules, path: &Path, timeout: Duration) -> Result<Vec<YaraMatch>> {
        let mut scanner = yara_x::Scanner::new(&loaded.rules);
        scanner.set_timeout(timeout);
        let results = scanner
            .scan_file(path)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(results
            .matching_rules()
            .map(|rule| to_match(&rule))
            .collect())
    }
}

fn to_match(rule: &yara_x::Rule) -> YaraMatch {
    let mut found = YaraMatch {
        rule: rule.identifier().to_string(),
        score: None,
        description: None,
        author: None,
        reference: None,
    };
    for (key, value) in rule.metadata() {
        match (key, value) {
            ("score", yara_x::MetaValue::Integer(v)) => found.score = Some(v),
            ("description", yara_x::MetaValue::String(v)) => {
                found.description = Some(v.to_string())
            }
            ("author", yara_x::MetaValue::String(v)) => found.author = Some(v.to_string()),
            ("reference", yara_x::MetaValue::String(v)) if v.starts_with("http") => {
                found.reference = Some(v.to_string())
            }
            _ => {}
        }
    }
    found
}

pub fn compile(source: &str) -> Result<(yara_x::Rules, usize)> {
    let mut compiler = yara_x::Compiler::new();
    compiler.relaxed_re_syntax(true);
    compiler.enable_includes(false);
    compiler.switch_all_warnings(false);
    // Rules that YARA-X rejects are skipped; the others are kept.
    if let Err(err) = compiler.add_source(source) {
        tracing::debug!("first YARA compile error: {err}");
    }
    let errors = compiler.errors().len();
    if errors > 0 {
        tracing::info!(
            skipped = errors,
            "some YARA rules are not supported by YARA-X and were skipped"
        );
    }
    let rules = compiler.build();
    let count = rules.iter().count();
    if count == 0 {
        bail!("no YARA rule could be compiled");
    }
    Ok((rules, count))
}

fn extract_rules(zip_bytes: &[u8], package: &str) -> Result<String> {
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).context("invalid rules archive")?;
    let wanted = format!("yara-rules-{package}.yar");
    let index = (0..archive.len())
        .find(|i| {
            archive
                .by_index(*i)
                .map(|f| f.name().ends_with(&wanted))
                .unwrap_or(false)
        })
        .with_context(|| format!("{wanted} not found in the rules archive"))?;
    let file = archive.by_index(index)?;
    if file.size() > MAX_RULES_SIZE {
        bail!("{wanted} is too large");
    }
    let mut source = String::new();
    file.take(MAX_RULES_SIZE).read_to_string(&mut source)?;
    Ok(source)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("no parent directory")?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    std::io::Write::write_all(&mut tmp, bytes)?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Waits until a YARA setting differs from `current`; false when the store is gone.
async fn yara_settings_change(
    changes: &mut tokio::sync::watch::Receiver<Arc<crate::settings::Settings>>,
    current: &YaraSettings,
) -> bool {
    loop {
        if changes.changed().await.is_err() {
            return false;
        }
        let next = changes.borrow_and_update().yara.clone();
        if next.enabled != current.enabled
            || next.package != current.package
            || next.update_interval_hours != current.update_interval_hours
        {
            return true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
        rule MAL_Test_Marker : FILE {
            meta:
                description = "Detects the FileFender test marker"
                author = "FileFender"
                reference = "https://example.com/marker"
                score = 80
            strings:
                $a = "FILEFENDER-TEST-MARKER"
            condition:
                $a
        }
        rule SUSP_Low_Score {
            meta:
                score = 50
            strings:
                $b = "low-score-marker"
            condition:
                $b
        }
        rule Broken_For_YaraX {
            strings:
                $c = "x"
            condition:
                $c and unknown_identifier
        }
    "#;

    #[test]
    fn invalid_rules_are_skipped_and_matches_carry_metadata() {
        let (rules, count) = compile(RULES).unwrap();
        assert_eq!(count, 2);
        let loaded = LoadedRules {
            rules,
            package: "core".into(),
            release: "test".into(),
            count,
            loaded_at: now_rfc3339(),
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.bin");
        std::fs::write(&path, b"header FILEFENDER-TEST-MARKER low-score-marker").unwrap();
        let mut matches = Yara::scan(&loaded, &path, Duration::from_secs(5)).unwrap();
        matches.sort_by(|a, b| a.rule.cmp(&b.rule));
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].rule, "MAL_Test_Marker");
        assert_eq!(matches[0].score, Some(80));
        assert_eq!(
            matches[0].description.as_deref(),
            Some("Detects the FileFender test marker")
        );
        assert_eq!(
            matches[0].reference.as_deref(),
            Some("https://example.com/marker")
        );
        assert_eq!(matches[1].score, Some(50));

        std::fs::write(&path, b"nothing to see").unwrap();
        assert!(
            Yara::scan(&loaded, &path, Duration::from_secs(5))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn extracts_the_package_from_a_zip() {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("packages/core/yara-rules-core.yar", options)
                .unwrap();
            std::io::Write::write_all(&mut zip, b"rule a { condition: true }").unwrap();
            zip.finish().unwrap();
        }
        let source = extract_rules(buf.get_ref(), "core").unwrap();
        assert!(source.contains("rule a"));
        assert!(extract_rules(buf.get_ref(), "full").is_err());
    }
}
