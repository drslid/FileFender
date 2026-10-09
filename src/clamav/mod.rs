//! Runs clamd as a supervised child and keeps its signatures current with freshclam.

pub mod client;
pub mod feeds;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

use crate::config::Config;
use crate::settings::{Settings, SettingsStore};
use crate::status::EngineStatus;
use crate::util::{now_rfc3339, rfc3339};

const DATABASES: [&str; 3] = ["main", "daily", "bytecode"];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DbInfo {
    pub name: String,
    pub version: u64,
    pub signatures: u64,
    pub built_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FeedState {
    pub id: &'static str,
    pub provider: &'static str,
    pub homepage: &'static str,
    pub enabled: bool,
    /// Database files downloaded so far, out of `expected`.
    pub files: usize,
    pub expected: usize,
    pub size: u64,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClamavState {
    pub status: EngineStatus,
    pub message: Option<String>,
    pub engine_version: Option<String>,
    pub databases: Vec<DbInfo>,
    pub feeds: Vec<FeedState>,
    pub signatures: u64,
    pub last_check: Option<String>,
    pub last_update: Option<String>,
    pub next_check: Option<String>,
    /// Identifies the third-party files on disk; part of the verdict cache key.
    #[serde(skip)]
    feeds_version: String,
}

impl ClamavState {
    /// When the loaded daily database was built: its age shows whether updates work.
    pub fn daily_built_at(&self) -> Option<OffsetDateTime> {
        let built = self.databases.iter().find(|d| d.name == "daily")?;
        OffsetDateTime::parse(
            built.built_at.as_deref()?,
            &time::format_description::well_known::Rfc3339,
        )
        .ok()
    }
}

pub struct Clamav {
    cfg: Arc<Config>,
    settings: Arc<SettingsStore>,
    socket: PathBuf,
    clamd_conf: PathBuf,
    freshclam_conf: PathBuf,
    state: RwLock<ClamavState>,
    freshclam_lock: Mutex<()>,
    update_now: tokio::sync::Notify,
    reschedule: tokio::sync::Notify,
    restart: tokio::sync::Notify,
}

impl Clamav {
    pub fn new(cfg: Arc<Config>, settings: Arc<SettingsStore>) -> Self {
        let socket = cfg.run_dir.join("clamd.sock");
        let clamd_conf = cfg.run_dir.join("clamd.conf");
        let freshclam_conf = cfg.run_dir.join("freshclam.conf");
        Clamav {
            cfg,
            settings,
            socket,
            clamd_conf,
            freshclam_conf,
            state: RwLock::new(ClamavState {
                status: EngineStatus::Starting,
                message: None,
                engine_version: None,
                databases: Vec::new(),
                feeds: Vec::new(),
                signatures: 0,
                last_check: None,
                last_update: None,
                next_check: None,
                feeds_version: String::new(),
            }),
            freshclam_lock: Mutex::new(()),
            update_now: tokio::sync::Notify::new(),
            reschedule: tokio::sync::Notify::new(),
            restart: tokio::sync::Notify::new(),
        }
    }

    /// For tests: talk to an already running clamd.
    #[cfg(test)]
    pub fn with_socket(cfg: Arc<Config>, settings: Arc<SettingsStore>, socket: PathBuf) -> Self {
        let clamav = Clamav::new(cfg, settings);
        let clamav = Clamav { socket, ..clamav };
        clamav.set_status(EngineStatus::Ready, None);
        clamav
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub fn state(&self) -> ClamavState {
        self.state.read().unwrap().clone()
    }

    /// Checks for new signatures now instead of waiting for the next interval.
    pub fn request_update(&self) {
        self.update_now.notify_one();
    }

    pub fn status(&self) -> EngineStatus {
        self.state.read().unwrap().status
    }

    /// Identifies the signature set; verdicts are only reused for the same value.
    pub fn signature_version(&self) -> String {
        let state = self.state.read().unwrap();
        let mut version = state
            .databases
            .iter()
            .map(|db| format!("{}:{}", db.name, db.version))
            .collect::<Vec<_>>()
            .join(",");
        if !state.feeds_version.is_empty() {
            version.push_str(&format!(",feeds:{}", state.feeds_version));
        }
        version
    }

    fn set_status(&self, status: EngineStatus, message: Option<String>) {
        let mut state = self.state.write().unwrap();
        state.status = status;
        state.message = message;
    }

    fn refresh_databases(&self) {
        let dir = self.cfg.clamav_db_dir();
        let databases = read_databases(&dir);
        let feeds = feed_states(&dir, &self.settings.get());
        let feeds_version = feeds_fingerprint(&dir);
        let mut state = self.state.write().unwrap();
        state.signatures = databases.iter().map(|d| d.signatures).sum();
        state.databases = databases;
        state.feeds = feeds;
        state.feeds_version = feeds_version;
    }

    pub async fn run(self: Arc<Self>) {
        if let Err(err) = self.prepare() {
            tracing::error!("cannot prepare ClamAV: {err:#}");
            self.set_status(EngineStatus::Error, Some(format!("{err:#}")));
            return;
        }

        let db_dir = self.cfg.clamav_db_dir();
        if !databases_present(&db_dir) {
            match seed_databases(&self.cfg.clamav_seed_dir, &db_dir) {
                Ok(true) => tracing::info!(
                    from = %self.cfg.clamav_seed_dir.display(),
                    "using the signatures shipped in the image; updates follow in a few minutes"
                ),
                Ok(false) => {}
                Err(err) => tracing::warn!("cannot copy the bundled signatures: {err:#}"),
            }
        }

        // Full downloads count against the ClamAV CDN rate limit: retry slowly.
        let mut retry = Duration::from_secs(300);
        while !databases_present(&db_dir) {
            self.set_status(
                EngineStatus::Downloading,
                Some("downloading the signature databases".into()),
            );
            tracing::info!("downloading ClamAV signatures (first start, about 110 MB)");
            match self.freshclam().await {
                Ok(_) if databases_present(&db_dir) => break,
                Ok(run) => {
                    let message = run.cooldown.map_or_else(
                        || "freshclam finished but the databases are incomplete".to_string(),
                        |until| format!("the ClamAV CDN rate-limits this server until {until}"),
                    );
                    tracing::warn!("{message}");
                    self.set_status(EngineStatus::Error, Some(message));
                }
                Err(err) => {
                    tracing::error!("signature download failed: {err:#}");
                    self.set_status(
                        EngineStatus::Error,
                        Some(format!("signature download failed: {err:#}")),
                    );
                }
            }
            tokio::time::sleep(retry).await;
            retry = (retry * 2).min(Duration::from_secs(7200));
        }
        self.refresh_databases();

        tokio::spawn(self.clone().update_loop());
        tokio::spawn(self.clone().settings_loop());

        let mut backoff = Duration::from_secs(1);
        loop {
            if let Err(err) = self.write_configs() {
                tracing::error!("cannot write the ClamAV configuration: {err:#}");
            }
            match self.run_clamd_once().await {
                Ok(()) => backoff = Duration::from_secs(1),
                Err(err) => {
                    tracing::error!("clamd: {err:#}");
                    self.set_status(EngineStatus::Error, Some(format!("{err:#}")));
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    }

    fn prepare(&self) -> Result<()> {
        for dir in [
            &self.cfg.run_dir,
            &self.cfg.clamav_db_dir(),
            &self.cfg.tmp_dir.join("clamd"),
        ] {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("cannot create {}", dir.display()))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.cfg.run_dir, std::fs::Permissions::from_mode(0o700))?;
            std::fs::set_permissions(
                self.cfg.tmp_dir.join("clamd"),
                std::fs::Permissions::from_mode(0o700),
            )?;
        }
        self.write_configs()?;
        remove_disabled_feeds(&self.cfg.clamav_db_dir(), &self.settings.get());
        Ok(())
    }

    fn write_configs(&self) -> Result<()> {
        let settings = self.settings.get();
        std::fs::write(
            &self.clamd_conf,
            clamd_conf(&self.cfg, &settings, &self.socket),
        )?;
        std::fs::write(&self.freshclam_conf, freshclam_conf(&self.cfg, &settings))?;
        Ok(())
    }

    /// Applies settings saved in the dashboard: detection options restart clamd (about ten
    /// seconds), feed changes download or remove databases, intervals reschedule the checks.
    async fn settings_loop(self: Arc<Self>) {
        let mut changes = self.settings.subscribe();
        let mut previous = self.settings.get();
        while changes.changed().await.is_ok() {
            let current = changes.borrow_and_update().clone();
            if let Err(err) = self.write_configs() {
                tracing::error!("cannot write the ClamAV configuration: {err:#}");
            }
            if clamd_settings_changed(&previous, &current) && self.status().usable() {
                tracing::info!("detection settings changed: restarting clamd");
                self.restart.notify_one();
            }
            let removed = remove_disabled_feeds(&self.cfg.clamav_db_dir(), &current);
            let added = current.feeds.iter().any(|f| !previous.feeds.contains(f));
            if added || current.clamav.private_mirror != previous.clamav.private_mirror {
                self.request_update();
            } else if removed
                && self.status().usable()
                && let Err(err) = self.reload().await
            {
                tracing::warn!("cannot reload the signatures: {err:#}");
            }
            if current.clamav.update_interval_hours != previous.clamav.update_interval_hours {
                self.reschedule.notify_one();
            }
            self.refresh_databases();
            previous = current;
        }
    }

    fn command(&self, program: &Path) -> Command {
        let mut command = Command::new(program);
        // Also read by libclamav when freshclam test-loads a download.
        if let Some(dir) = &self.cfg.clamav_certs_dir {
            command.env("CVD_CERTS_DIR", dir);
        }
        // Children are spawned from runtime worker threads, which live as long as the process.
        unsafe {
            command.pre_exec(|| {
                nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGTERM)
                    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
            });
        }
        command
    }

    /// Starts clamd, waits until it answers, then returns when it exits.
    async fn run_clamd_once(&self) -> Result<()> {
        self.set_status(
            EngineStatus::Loading,
            Some("loading signatures into memory".into()),
        );
        let _ = std::fs::remove_file(&self.socket);
        let mut child = self
            .command(&self.cfg.clamd_bin)
            .arg("--foreground")
            .arg(format!("--config-file={}", self.clamd_conf.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("cannot start {}", self.cfg.clamd_bin.display()))?;
        forward_output(&mut child, "clamd", None);

        let started = tokio::time::Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                bail!("clamd exited during startup ({status})");
            }
            if client::ping(&self.socket).await.is_ok() {
                break;
            }
            if started.elapsed() > Duration::from_secs(900) {
                bail!("clamd did not become ready within 15 minutes");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        self.refresh_version().await;
        self.set_status(EngineStatus::Ready, None);
        tracing::info!(
            seconds = started.elapsed().as_secs(),
            version = self.signature_version(),
            "clamd is ready"
        );

        let status = tokio::select! {
            status = child.wait() => status?,
            _ = self.restart.notified() => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                tracing::info!("clamd stopped to apply the new settings");
                return Ok(());
            }
        };
        bail!("clamd exited ({status})")
    }

    pub(crate) async fn refresh_version(&self) {
        if let Ok(reply) = client::version(&self.socket).await
            && let Some((engine, _)) = client::parse_version(&reply)
        {
            self.state.write().unwrap().engine_version = Some(engine);
        }
        self.refresh_databases();
    }

    async fn update_loop(self: Arc<Self>) {
        // The first check runs a few minutes after start: bundled signatures may be days old.
        let mut due = tokio::time::Instant::now() + Duration::from_secs(300);
        loop {
            // Spread checks so that many installations do not hit the mirrors together.
            let jitter = Duration::from_secs(u64::from(crate::util::random_bytes::<1>()[0]) * 7);
            let wait = due.saturating_duration_since(tokio::time::Instant::now()) + jitter;
            self.state.write().unwrap().next_check =
                Some(rfc3339(OffsetDateTime::now_utc() + wait));
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = self.update_now.notified() => tracing::info!("signature update requested"),
                _ = self.reschedule.notified() => {
                    // A shorter interval brings the next check forward; a longer one applies after it.
                    due = due.min(tokio::time::Instant::now() + self.interval());
                    continue;
                }
            }
            if let Err(err) = self.update_once().await {
                tracing::warn!("signature update failed: {err:#}");
            }
            due = tokio::time::Instant::now() + self.interval();
        }
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.settings.get().clamav.update_interval_hours) * 3600)
    }

    pub async fn update_once(&self) -> Result<bool> {
        let before = self.signature_version_on_disk();
        let run = self.freshclam().await?;
        let after = self.signature_version_on_disk();
        {
            let mut state = self.state.write().unwrap();
            state.last_check = Some(now_rfc3339());
            if state.status.usable() {
                state.message = run.cooldown.map(|until| {
                    format!("updates paused by the ClamAV CDN rate limit until {until}")
                });
            }
        }
        self.refresh_databases();
        if before == after {
            tracing::info!(version = after, "ClamAV signatures are up to date");
            return Ok(false);
        }
        tracing::info!(
            from = before,
            to = after,
            "new ClamAV signatures downloaded"
        );
        self.state.write().unwrap().last_update = Some(now_rfc3339());
        if self.status().usable() {
            self.reload().await?;
        }
        Ok(true)
    }

    pub(crate) async fn reload(&self) -> Result<()> {
        self.set_status(
            EngineStatus::Reloading,
            Some("loading new signatures".into()),
        );
        let target = read_databases(&self.cfg.clamav_db_dir());
        client::reload(&self.socket).await?;
        let started = tokio::time::Instant::now();
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if let Ok(reply) = client::version(&self.socket).await
                && let Some((_, Some(daily))) = client::parse_version(&reply)
                && target
                    .iter()
                    .any(|db| db.name == "daily" && db.version == daily)
            {
                break;
            }
            if started.elapsed() > Duration::from_secs(600) {
                bail!("clamd did not load the new signatures within 10 minutes");
            }
        }
        self.refresh_version().await;
        self.set_status(EngineStatus::Ready, None);
        tracing::info!(
            seconds = started.elapsed().as_secs(),
            "clamd reloaded its signatures"
        );
        Ok(())
    }

    fn signature_version_on_disk(&self) -> String {
        let dir = self.cfg.clamav_db_dir();
        let mut version = read_databases(&dir)
            .iter()
            .map(|db| format!("{}:{}", db.name, db.version))
            .collect::<Vec<_>>()
            .join(",");
        let feeds = feeds_fingerprint(&dir);
        if !feeds.is_empty() {
            version.push_str(&format!(",feeds:{feeds}"));
        }
        version
    }

    async fn freshclam(&self) -> Result<FreshclamRun> {
        let _guard = self.freshclam_lock.lock().await;
        let mut child = self
            .command(&self.cfg.freshclam_bin)
            .arg(format!("--config-file={}", self.freshclam_conf.display()))
            .arg("--stdout")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("cannot start {}", self.cfg.freshclam_bin.display()))?;
        let cooldown = Arc::new(std::sync::Mutex::new(None));
        let readers = forward_output(&mut child, "freshclam", Some(cooldown.clone()));
        let status = tokio::time::timeout(Duration::from_secs(1800), child.wait())
            .await
            .context("freshclam did not finish within 30 minutes")??;
        for reader in readers {
            let _ = reader.await;
        }
        if !status.success() {
            bail!("freshclam failed ({status})");
        }
        let cooldown = cooldown.lock().unwrap().take();
        Ok(FreshclamRun { cooldown })
    }
}

struct FreshclamRun {
    /// Set when the CDN answered 429: freshclam will not download before this time.
    cooldown: Option<String>,
}

type Capture = Arc<std::sync::Mutex<Option<String>>>;

fn forward_output(
    child: &mut Child,
    target: &'static str,
    capture: Option<Capture>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut readers = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        readers.push(tokio::spawn(forward_lines(
            BufReader::new(stdout),
            target,
            capture.clone(),
        )));
    }
    if let Some(stderr) = child.stderr.take() {
        readers.push(tokio::spawn(forward_lines(
            BufReader::new(stderr),
            target,
            capture,
        )));
    }
    readers
}

async fn forward_lines<R: tokio::io::AsyncRead + Unpin>(
    reader: BufReader<R>,
    source: &'static str,
    capture: Option<Capture>,
) {
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim();
        if line.is_empty() || line.chars().all(|c| c == '-' || c == '*') {
            continue;
        }
        if let Some(capture) = &capture
            && let Some((_, until)) = line.split_once("cool-down until after:")
        {
            *capture.lock().unwrap() = Some(until.trim().to_string());
        }
        let lower = line.to_ascii_lowercase();
        if lower.contains("error") || lower.contains("warning") {
            tracing::warn!(source, "{line}");
        } else {
            tracing::info!(source, "{line}");
        }
    }
}

/// Copies the signatures shipped in the image when the data volume has none yet.
pub fn seed_databases(seed: &Path, target: &Path) -> Result<bool> {
    if seed == target || !databases_present(seed) {
        return Ok(false);
    }
    for entry in std::fs::read_dir(seed)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !(name.ends_with(".cvd") || name.ends_with(".cld") || name.ends_with(".sign")) {
            continue;
        }
        let tmp = target.join(format!(".{name}.seed"));
        std::fs::copy(&path, &tmp)?;
        std::fs::rename(&tmp, target.join(name))?;
    }
    Ok(databases_present(target))
}

pub fn databases_present(dir: &Path) -> bool {
    ["main", "daily"].iter().all(|name| {
        ["cvd", "cld"]
            .iter()
            .any(|ext| dir.join(format!("{name}.{ext}")).is_file())
    })
}

pub fn read_databases(dir: &Path) -> Vec<DbInfo> {
    let mut found = Vec::new();
    for name in DATABASES {
        let best = ["cld", "cvd"]
            .iter()
            .filter_map(|ext| read_header(&dir.join(format!("{name}.{ext}"))))
            .max_by_key(|h| h.0);
        if let Some((version, signatures, built)) = best {
            found.push(DbInfo {
                name: name.to_string(),
                version,
                signatures,
                built_at: built.map(rfc3339),
            });
        }
    }
    found
}

fn read_header(path: &Path) -> Option<(u64, u64, Option<OffsetDateTime>)> {
    use std::io::Read;
    let mut header = [0u8; 512];
    let mut file = std::fs::File::open(path).ok()?;
    let n = file.read(&mut header).ok()?;
    parse_header(&header[..n])
}

/// CVD/CLD header: `ClamAV-VDB:<time>:<version>:<sigs>:<level>:<md5>:<dsig>:<builder>:<stime>`.
pub fn parse_header(header: &[u8]) -> Option<(u64, u64, Option<OffsetDateTime>)> {
    let text = String::from_utf8_lossy(header);
    let text = text.strip_prefix("ClamAV-VDB:")?;
    let fields: Vec<&str> = text.trim_end_matches(['\0', ' ']).split(':').collect();
    let version = fields.get(1)?.trim().parse().ok()?;
    let signatures = fields.get(2)?.trim().parse().ok()?;
    let built = fields
        .get(7)
        .and_then(|s| s.trim().parse::<i64>().ok())
        .and_then(|ts| OffsetDateTime::from_unix_timestamp(ts).ok());
    Some((version, signatures, built))
}

fn yes(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Settings written into clamd.conf: changing one restarts clamd.
fn clamd_settings_changed(a: &Settings, b: &Settings) -> bool {
    a.clamav.alert_encrypted != b.clamav.alert_encrypted
        || a.clamav.alert_macros != b.clamav.alert_macros
        || a.clamav.detect_pua != b.clamav.detect_pua
        || a.clamav.heuristics != b.clamav.heuristics
        || a.clamav.broken_executables != b.clamav.broken_executables
        || a.clamav.phishing != b.clamav.phishing
        || a.clamav.max_recursion != b.clamav.max_recursion
        || a.clamav.max_files != b.clamav.max_files
        || a.limits.max_file_size != b.limits.max_file_size
        || a.limits.scan_timeout_seconds != b.limits.scan_timeout_seconds
}

fn file_stamp(path: &Path) -> Option<(u64, OffsetDateTime)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.len(), OffsetDateTime::from(meta.modified().ok()?)))
}

pub fn feed_states(dir: &Path, settings: &Settings) -> Vec<FeedState> {
    feeds::FEEDS
        .iter()
        .map(|feed| {
            let stamps: Vec<_> = feed
                .files()
                .filter_map(|f| file_stamp(&dir.join(f)))
                .collect();
            FeedState {
                id: feed.id,
                provider: feed.provider,
                homepage: feed.homepage,
                enabled: settings.feeds.iter().any(|f| f == feed.id),
                files: stamps.len(),
                expected: feed.urls.len(),
                size: stamps.iter().map(|s| s.0).sum(),
                updated_at: stamps.iter().map(|s| s.1).max().map(rfc3339),
            }
        })
        .collect()
}

/// Short hash of the third-party files present: changes whenever one is updated.
fn feeds_fingerprint(dir: &Path) -> String {
    let mut hasher = Sha256::new();
    let mut any = false;
    for file in feeds::all_files() {
        if let Some((len, modified)) = file_stamp(&dir.join(file)) {
            any = true;
            hasher.update(format!(
                "{file}:{len}:{}\n",
                modified.unix_timestamp_nanos()
            ));
        }
    }
    if any {
        hex::encode(&hasher.finalize()[..6])
    } else {
        String::new()
    }
}

/// Deletes the databases of feeds turned off; returns whether clamd must reload.
fn remove_disabled_feeds(dir: &Path, settings: &Settings) -> bool {
    let mut removed = false;
    for feed in feeds::FEEDS {
        if settings.feeds.iter().any(|f| f == feed.id) {
            continue;
        }
        for file in feed.files() {
            if std::fs::remove_file(dir.join(file)).is_ok() {
                tracing::info!(feed = feed.id, file, "removed a turned-off signature feed");
                removed = true;
            }
        }
    }
    removed
}

pub fn clamd_conf(cfg: &Config, settings: &Settings, socket: &Path) -> String {
    let clamav = &settings.clamav;
    let max_file = settings.limits.max_file_size;
    let scan_timeout = Duration::from_secs(settings.limits.scan_timeout_seconds);
    // Data extracted from archives counts towards MaxScanSize.
    let max_scan = (max_file.saturating_mul(4)).clamp(400 * 1024 * 1024, 4000 * 1024 * 1024);
    let mut conf = format!(
        "# Generated by FileFender. Change these values in the dashboard settings.\n\
Foreground yes\n\
LocalSocket {socket}\n\
LocalSocketMode 600\n\
FixStaleSocket yes\n\
DatabaseDirectory {db}\n\
TemporaryDirectory {tmp}\n\
LogTime no\n\
LogClean no\n\
LogVerbose no\n\
MaxThreads {threads}\n\
MaxQueue {queue}\n\
ReadTimeout {read_timeout}\n\
CommandReadTimeout 30\n\
IdleTimeout 60\n\
SelfCheck 3600\n\
ConcurrentDatabaseReload {concurrent}\n\
MaxScanTime {scan_ms}\n\
MaxScanSize {max_scan}\n\
MaxFileSize {max_file}\n\
StreamMaxLength {max_file}\n\
MaxRecursion {recursion}\n\
MaxFiles {files}\n\
AlertExceedsMax yes\n\
AlertEncrypted {encrypted}\n\
AlertBrokenExecutables {broken}\n\
AlertOLE2Macros {macros}\n\
AlertPartitionIntersection yes\n\
HeuristicAlerts {heuristics}\n\
HeuristicScanPrecedence no\n\
PhishingSignatures {phishing}\n\
PhishingScanURLs {phishing}\n\
DetectPUA {pua}\n\
Bytecode yes\n\
EnableShutdownCommand no\n\
EnableStatsCommand no\n\
EnableVersionCommand yes\n\
EnableReloadCommand yes\n",
        socket = socket.display(),
        db = cfg.clamav_db_dir().display(),
        tmp = cfg.tmp_dir.join("clamd").display(),
        threads = cfg.max_concurrent_scans,
        queue = cfg.max_pending_scans.max(16),
        read_timeout = scan_timeout.as_secs().max(30),
        concurrent = yes(!cfg.low_memory),
        scan_ms = scan_timeout.as_millis(),
        recursion = clamav.max_recursion,
        files = clamav.max_files,
        encrypted = yes(clamav.alert_encrypted),
        broken = yes(clamav.broken_executables),
        macros = yes(clamav.alert_macros),
        heuristics = yes(clamav.heuristics),
        phishing = yes(clamav.phishing),
        pua = yes(clamav.detect_pua),
    );
    if let Some(dir) = &cfg.clamav_certs_dir {
        conf.push_str(&format!("CVDCertsDirectory {}\n", dir.display()));
    }
    conf
}

pub fn freshclam_conf(cfg: &Config, settings: &Settings) -> String {
    let mut conf = format!(
        "# Generated by FileFender. Change these values in the dashboard settings.\n\
DatabaseDirectory {db}\n\
DatabaseMirror database.clamav.net\n\
DNSDatabaseInfo current.cvd.clamav.net\n\
ScriptedUpdates yes\n\
Bytecode yes\n\
TestDatabases {test}\n\
LogTime no\n\
LogVerbose no\n\
ConnectTimeout 30\n\
ReceiveTimeout 900\n",
        db = cfg.clamav_db_dir().display(),
        test = yes(!cfg.low_memory),
    );
    if let Some(mirror) = &settings.clamav.private_mirror {
        conf.push_str(&format!("PrivateMirror {mirror}\n"));
    }
    for feed in feeds::FEEDS {
        if settings.feeds.iter().any(|f| f == feed.id) {
            for url in feed.urls {
                conf.push_str(&format!("DatabaseCustomURL {url}\n"));
            }
        }
    }
    if let Some(dir) = &cfg.clamav_certs_dir {
        conf.push_str(&format!("CVDCertsDirectory {}\n", dir.display()));
    }
    conf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(vars: &[(&str, &str)]) -> Config {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| (format!("FILEFENDER_{k}"), v.to_string()))
            .collect();
        Config::from_lookup(|name| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()))
            .unwrap()
    }

    #[test]
    fn parses_cvd_headers() {
        let mut header =
            b"ClamAV-VDB:08 Oct 2026 07-52 -0400:27788:2071122:90:abc123:sig/+=:builder:1791460320"
                .to_vec();
        header.resize(512, b' ');
        let (version, sigs, built) = parse_header(&header).unwrap();
        assert_eq!((version, sigs), (27788, 2071122));
        assert_eq!(built.unwrap().unix_timestamp(), 1791460320);
        assert!(parse_header(b"PK\x03\x04garbage").is_none());
    }

    #[test]
    fn clamd_config_is_hardened() {
        let cfg = config(&[("MAX_FILE_SIZE", "50M")]);
        let settings = Settings::from_config(&cfg);
        let conf = clamd_conf(&cfg, &settings, Path::new("/run/filefender/clamd.sock"));
        for line in [
            "AlertExceedsMax yes",
            "AlertEncrypted yes",
            "LocalSocketMode 600",
            "EnableShutdownCommand no",
            "MaxFileSize 52428800",
            "MaxScanSize 419430400",
            "ConcurrentDatabaseReload yes",
            "PhishingSignatures yes",
            "MaxRecursion 17",
        ] {
            assert!(conf.contains(line), "missing {line}");
        }
        assert!(!conf.contains("TCPSocket"), "clamd must not listen on TCP");
        assert!(!conf.contains("User "), "clamd must not switch users");

        let low = config(&[("LOW_MEMORY", "true")]);
        let low_settings = Settings::from_config(&low);
        assert!(
            clamd_conf(&low, &low_settings, Path::new("/s"))
                .contains("ConcurrentDatabaseReload no")
        );
        assert!(freshclam_conf(&low, &low_settings).contains("TestDatabases no"));
    }

    #[test]
    fn settings_shape_both_configurations() {
        let cfg = config(&[]);
        let mut settings = Settings::from_config(&cfg);
        settings.clamav.detect_pua = true;
        settings.clamav.max_recursion = 8;
        settings.clamav.private_mirror = Some("https://mirror.example.com".into());
        settings.feeds = vec!["urlhaus".into(), "interserver".into()];
        let clamd = clamd_conf(&cfg, &settings, Path::new("/s"));
        assert!(clamd.contains("DetectPUA yes") && clamd.contains("MaxRecursion 8"));
        let fresh = freshclam_conf(&cfg, &settings);
        assert!(fresh.contains("PrivateMirror https://mirror.example.com"));
        assert!(fresh.contains("DatabaseCustomURL https://urlhaus.abuse.ch/downloads/urlhaus.ndb"));
        assert!(fresh.contains("DatabaseCustomURL https://sigs.interserver.net/shell.ldb"));
        assert!(!fresh.contains("sanesecurity"));

        let previous = Settings::from_config(&cfg);
        assert!(clamd_settings_changed(&previous, &settings));
        let mut feeds_only = previous.clone();
        feeds_only.feeds = vec!["urlhaus".into()];
        assert!(
            !clamd_settings_changed(&previous, &feeds_only),
            "feeds only need a reload"
        );
    }

    #[test]
    fn turned_off_feeds_are_deleted() {
        let dir = tempfile::tempdir().unwrap();
        for file in ["urlhaus.ndb", "shell.ldb", "daily.cvd"] {
            std::fs::write(dir.path().join(file), file).unwrap();
        }
        let mut settings = Settings::from_config(&config(&[]));
        settings.feeds = vec!["urlhaus".into()];
        let before = feeds_fingerprint(dir.path());
        assert!(remove_disabled_feeds(dir.path(), &settings));
        assert!(dir.path().join("urlhaus.ndb").is_file());
        assert!(!dir.path().join("shell.ldb").exists());
        assert!(
            dir.path().join("daily.cvd").is_file(),
            "official databases stay"
        );
        assert_ne!(before, feeds_fingerprint(dir.path()));
        let states = feed_states(dir.path(), &settings);
        let urlhaus = states.iter().find(|f| f.id == "urlhaus").unwrap();
        assert!(urlhaus.enabled && urlhaus.files == 1 && urlhaus.updated_at.is_some());
    }

    #[test]
    fn detects_missing_databases() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!databases_present(dir.path()));
        std::fs::write(dir.path().join("main.cvd"), b"x").unwrap();
        assert!(!databases_present(dir.path()));
        std::fs::write(dir.path().join("daily.cld"), b"x").unwrap();
        assert!(databases_present(dir.path()));
    }

    #[test]
    fn seeds_signatures_from_the_image_once() {
        let seed = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        assert!(!seed_databases(seed.path(), target.path()).unwrap());
        for name in [
            "main.cvd",
            "daily.cvd",
            "daily-28147.cvd.sign",
            "freshclam.dat",
        ] {
            std::fs::write(seed.path().join(name), name).unwrap();
        }
        assert!(seed_databases(seed.path(), target.path()).unwrap());
        assert!(target.path().join("daily-28147.cvd.sign").is_file());
        assert!(
            !target.path().join("freshclam.dat").exists(),
            "freshclam state is not copied"
        );
    }

    #[tokio::test]
    async fn captures_the_cdn_cooldown() {
        let text = b"WARNING: FreshClam received error code 429\nWARNING: You are on cool-down until after: 2026-10-09 01:47:26\n";
        let capture: Capture = Arc::new(std::sync::Mutex::new(None));
        forward_lines(
            BufReader::new(&text[..]),
            "freshclam",
            Some(capture.clone()),
        )
        .await;
        assert_eq!(
            capture.lock().unwrap().as_deref(),
            Some("2026-10-09 01:47:26")
        );
    }
}
