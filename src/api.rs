use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use axum::extract::{ConnectInfo, FromRequest, FromRequestParts, Multipart, Path, Request, State};
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::http::request::Parts;
use axum::http::{Extensions, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::StreamExt;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::audit::Audit;
use crate::config::{Config, MAX_FILE_SIZE_LIMIT};
use crate::hashlist::HashLists;
use crate::keys::{KeyStore, StoredKey};
use crate::notify::{Alert, Event, Level, Notifier};
use crate::scan::{ScanError, ScanReport, Scanner, Upload, Verdict};
use crate::settings::{SettingsStore, networks_allow};
use crate::users::{Role, Sessions, UserStore};
use crate::util::sanitize_filename;
use crate::web;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_AUTH_FAILURES: u32 = 20;
const MULTIPART_OVERHEAD: u64 = 1024 * 1024;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TlsState {
    pub mode: &'static str,
    pub domain: Option<String>,
    pub certificate: &'static str,
    pub detail: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub keys: Arc<KeyStore>,
    pub users: Arc<UserStore>,
    pub sessions: Sessions,
    pub scanner: Arc<Scanner>,
    pub settings: Arc<SettingsStore>,
    pub hashlists: Arc<HashLists>,
    pub audit: Arc<Audit>,
    pub notifier: Arc<Notifier>,
    pub tls: Arc<RwLock<TlsState>>,
    started: Instant,
    started_at: String,
    auth_failures: moka::sync::Cache<IpAddr, Arc<AtomicU32>>,
}

impl AppState {
    pub fn new(
        cfg: Arc<Config>,
        keys: Arc<KeyStore>,
        users: Arc<UserStore>,
        scanner: Arc<Scanner>,
        audit: Arc<Audit>,
        notifier: Arc<Notifier>,
    ) -> Self {
        let tls = TlsState {
            mode: if cfg.tls() { "acme" } else { "off" },
            domain: cfg.domain.clone(),
            certificate: if cfg.tls() { "pending" } else { "none" },
            detail: None,
            updated_at: None,
        };
        AppState {
            cfg,
            keys,
            users,
            sessions: Sessions::default(),
            settings: scanner.settings.clone(),
            hashlists: scanner.hashlists.clone(),
            scanner,
            audit,
            notifier,
            tls: Arc::new(RwLock::new(tls)),
            started: Instant::now(),
            started_at: crate::util::now_rfc3339(),
            auth_failures: moka::sync::Cache::builder()
                .max_capacity(100_000)
                .time_to_live(std::time::Duration::from_secs(900))
                .build(),
        }
    }
}

pub fn router(state: AppState) -> Router {
    // The real limit comes from the settings; this one only bounds what axum buffers.
    let upload_limit = (MAX_FILE_SIZE_LIMIT + MULTIPART_OVERHEAD) as usize;
    let dashboard = Router::new()
        .route("/", get(web::index))
        .route("/assets/{name}", get(web::asset))
        .merge(crate::account::routes())
        .merge(crate::manage::routes())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            dashboard_guard,
        ));
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route(
            "/v1/scan",
            post(scan).layer(axum::extract::DefaultBodyLimit::max(upload_limit)),
        )
        .route("/v1/hashes/{sha256}", get(lookup_hash))
        .route("/v1/status", get(status))
        .route("/metrics", get(metrics))
        .merge(dashboard)
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .with_state(state)
}

fn dashboard_forbidden() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "dashboard_forbidden",
        "the dashboard cannot be opened from this address",
    )
}

/// Pages and account endpoints answer only the networks allowed in the settings.
async fn dashboard_guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let ip = client_ip(request.headers(), request.extensions(), &state);
    if !state.settings.get().dashboard_allows(ip) {
        tracing::warn!(client = %ip, "dashboard request refused by the network allowlist");
        return dashboard_forbidden().into_response();
    }
    next.run(request).await
}

pub(crate) fn require_dashboard_network(parts: &Parts, state: &AppState) -> Result<(), ApiError> {
    let ip = client_ip(&parts.headers, &parts.extensions, state);
    if state.settings.get().dashboard_allows(ip) {
        Ok(())
    } else {
        Err(dashboard_forbidden())
    }
}

/// Plain HTTP listener used next to HTTPS: health probes stay local, the rest is redirected.
pub fn redirect_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .fallback(redirect_to_https)
        .with_state(state)
}

async fn redirect_to_https(State(state): State<AppState>, uri: Uri) -> Response {
    let domain = state.cfg.domain.clone().unwrap_or_default();
    let port = match state.cfg.https_port {
        443 => String::new(),
        port => format!(":{port}"),
    };
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    Redirect::permanent(&format!("https://{domain}{port}{path}")).into_response()
}

async fn security_headers(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let set = |headers: &mut HeaderMap, name: &'static str, value: &'static str| {
        headers.insert(name, HeaderValue::from_static(value));
    };
    set(headers, "x-content-type-options", "nosniff");
    set(headers, "referrer-policy", "no-referrer");
    set(headers, "x-frame-options", "DENY");
    set(headers, "cross-origin-opener-policy", "same-origin");
    set(headers, "cross-origin-resource-policy", "same-origin");
    set(
        headers,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=()",
    );
    set(
        headers,
        "content-security-policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
         connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    );
    if state.cfg.tls() {
        set(headers, "strict-transport-security", "max-age=31536000");
    }
    if !headers.contains_key(header::CACHE_CONTROL) {
        set(headers, "cache-control", "no-store");
    }
    response
}

pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    retry_after: Option<u64>,
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            code,
            message: message.into(),
            retry_after: None,
        }
    }

    pub(crate) fn retry(mut self, seconds: u64) -> Self {
        self.retry_after = Some(seconds);
        self
    }

    /// Logs the cause and answers 500 without details.
    pub(crate) fn internal(err: impl std::fmt::Display) -> Self {
        tracing::error!("{err:#}");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "internal error, see the server logs",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(json!({ "error": { "code": self.code, "message": self.message } }));
        let mut response = (self.status, body).into_response();
        if let Some(seconds) = self.retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"filefender\""),
            );
        }
        response
    }
}

impl From<ScanError> for ApiError {
    fn from(err: ScanError) -> Self {
        match err {
            ScanError::NotReady(_) => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "not_ready",
                err.to_string(),
            )
            .retry(30),
            ScanError::Busy => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "busy",
                "every scan slot is busy, retry shortly",
            )
            .retry(5),
            ScanError::Unavailable { .. } => {
                tracing::error!("scan failed: {err}");
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "engine_unavailable",
                    err.to_string(),
                )
                .retry(10)
            }
            ScanError::Failed { .. } => {
                tracing::error!("scan failed: {err}");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "scan_failed",
                    err.to_string(),
                )
            }
        }
    }
}

/// Client address: the TCP peer, or the last `X-Forwarded-For` hop behind a trusted proxy.
fn client_ip(headers: &HeaderMap, extensions: &Extensions, state: &AppState) -> IpAddr {
    if state.cfg.trust_proxy_headers
        && let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse().ok())
    {
        return ip;
    }
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::from([0, 0, 0, 0]), |c| c.0.ip())
}

/// IPv6 clients are throttled per /64, the smallest block a user usually controls.
fn throttle_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            let mut segments = v6.segments();
            segments[4..].fill(0);
            IpAddr::from(segments)
        }
        v4 => v4,
    }
}

pub enum Caller {
    Key(Arc<StoredKey>),
    Dashboard { username: String, role: Role },
}

impl std::fmt::Display for Caller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Caller::Key(key) => write!(f, "key {}", key.label),
            Caller::Dashboard { username, .. } => write!(f, "dashboard {username}"),
        }
    }
}

/// An application with an API key, or a person signed in to the dashboard.
pub struct Authenticated(pub Caller);

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let ip = client_ip(&parts.headers, &parts.extensions, state);
        check_throttle(state, ip)?;
        let presented = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .or_else(|| parts.headers.get("x-api-key").and_then(|v| v.to_str().ok()))
            .map(str::trim);
        let Some(presented) = presented else {
            if let Some(session) = crate::account::dashboard_session(parts, state)? {
                return Ok(Authenticated(Caller::Dashboard {
                    username: session.user.username.clone(),
                    role: session.user.role,
                }));
            }
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "send your API key in the Authorization: Bearer header",
            ));
        };
        let Some(key) = state.keys.verify(presented) else {
            record_failure(state, ip);
            tracing::warn!(client = %ip, "rejected an invalid API key");
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "invalid API key",
            ));
        };
        if key.expired() {
            tracing::warn!(client = %ip, key = %key.label, "rejected an expired API key");
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "key_expired",
                "this API key has expired",
            ));
        }
        if !networks_allow(&key.allowed_networks, ip) {
            tracing::warn!(client = %ip, key = %key.label, "API key used from a network it does not allow");
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "ip_not_allowed",
                "this API key cannot be used from this address",
            ));
        }
        if let Err(wait) = state.keys.allow_request(&key) {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                format!(
                    "this API key is limited to {} requests per minute",
                    key.rate_per_minute.unwrap_or_default()
                ),
            )
            .retry(wait));
        }
        state.keys.touch(&key, ip);
        Ok(Authenticated(Caller::Key(key)))
    }
}

/// Too many failures from an address (IPv6: its /64) block it for 15 minutes.
pub(crate) fn check_throttle(state: &AppState, ip: IpAddr) -> Result<(), ApiError> {
    if state
        .auth_failures
        .get(&throttle_key(ip))
        .is_some_and(|n| n.load(Ordering::Relaxed) >= MAX_AUTH_FAILURES)
    {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_failures",
            "too many failed attempts from this address, retry later",
        )
        .retry(900));
    }
    Ok(())
}

pub(crate) fn record_failure(state: &AppState, ip: IpAddr) {
    let failures = state
        .auth_failures
        .get_with(throttle_key(ip), || Arc::new(AtomicU32::new(0)))
        .fetch_add(1, Ordering::Relaxed)
        + 1;
    if failures == MAX_AUTH_FAILURES {
        state.audit.record(
            "security.throttled",
            "-",
            Some(ip),
            format!("{MAX_AUTH_FAILURES} failed attempts: blocked for 15 minutes"),
        );
    }
}

/// The client address (behind a trusted proxy, the one it reports).
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(client_ip(
            &parts.headers,
            &parts.extensions,
            state,
        )))
    }
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok", "version": VERSION }))
}

async fn readyz(State(state): State<AppState>) -> Response {
    if state.scanner.not_ready_reason().is_none() {
        Json(json!({ "status": "ready" })).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "starting" })),
        )
            .into_response()
    }
}

async fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such endpoint")
}

async fn scan(
    State(state): State<AppState>,
    Authenticated(caller): Authenticated,
    ClientIp(ip): ClientIp,
    request: Request,
) -> Result<Json<ScanReport>, ApiError> {
    if let Caller::Dashboard { role, .. } = &caller
        && *role < Role::Operator
    {
        return Err(crate::account::forbidden());
    }
    let _slot = state.scanner.try_reserve().ok_or_else(|| {
        state.scanner.stats.record_rejected();
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "queue_full",
            "too many scans waiting, retry shortly",
        )
        .retry(5)
    })?;
    if let Some(reason) = state.scanner.not_ready_reason() {
        return Err(ScanError::NotReady(reason).into());
    }
    let limit = state.settings.get().limits.max_file_size;
    if let Some(length) = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        && length > limit + MULTIPART_OVERHEAD
    {
        return Err(too_large(limit));
    }

    let upload = tokio::time::timeout(state.cfg.upload_timeout, receive(&state, request, limit))
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::REQUEST_TIMEOUT,
                "upload_timeout",
                "the upload took too long",
            )
        })??;
    let report = state.scanner.scan(upload).await?;
    tracing::info!(
        by = %caller,
        verdict = ?report.verdict,
        sha256 = %report.file.sha256,
        size = report.file.size.unwrap_or(0),
        ms = report.duration_ms,
        cached = report.cached,
        threats = %report.threats.iter().map(|t| t.name.as_str()).collect::<Vec<_>>().join(","),
        "scan"
    );
    if report.verdict != Verdict::Clean {
        alert_threat(&state, &report, &caller, ip);
    }
    Ok(Json(report))
}

/// One alert per file and hour, whoever sends it again.
fn alert_threat(state: &AppState, report: &ScanReport, caller: &Caller, ip: IpAddr) {
    let malicious = report.verdict == Verdict::Malicious;
    let name = report.file.name.as_deref().unwrap_or("unnamed file");
    let threats: Vec<String> = report
        .threats
        .iter()
        .map(|t| format!("{} ({})", t.name, t.engine))
        .collect();
    state.notifier.send_once(
        format!("threat:{}", report.file.sha256),
        Alert {
            event: Event::Threats,
            level: if malicious {
                Level::Critical
            } else {
                Level::Warning
            },
            title: format!(
                "{} file: {name}",
                if malicious { "Malicious" } else { "Suspicious" }
            ),
            text: format!(
                "{}\nSHA-256 {}\nSent by {caller} from {ip}",
                threats.join(", "),
                report.file.sha256
            ),
            data: json!({
                "verdict": report.verdict,
                "file": report.file,
                "threats": report.threats,
                "caller": caller.to_string(),
                "ip": ip.to_string(),
            }),
        },
    );
}

fn too_large(limit: u64) -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "file_too_large",
        format!("files are limited to {limit} bytes"),
    )
}

/// Streams the upload to a private temporary file while hashing it.
async fn receive(state: &AppState, request: Request, limit: u64) -> Result<Upload, ApiError> {
    let internal = |e: std::io::Error| {
        tracing::error!("cannot store the upload: {e}");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            "cannot store the upload",
        )
    };
    let file = tempfile::Builder::new()
        .prefix("upload-")
        .tempfile_in(state.cfg.tmp_dir.join("uploads"))
        .map_err(internal)?;
    let mut writer = tokio::fs::File::from_std(file.as_file().try_clone().map_err(internal)?);
    let mut hasher = Sha256::new();
    let mut head: Vec<u8> = Vec::with_capacity(8192);
    let mut size: u64 = 0;

    let mut write = async |chunk: &[u8]| -> Result<(), ApiError> {
        size += chunk.len() as u64;
        if size > limit {
            return Err(too_large(limit));
        }
        hasher.update(chunk);
        if head.len() < 8192 {
            let take = (8192 - head.len()).min(chunk.len());
            head.extend_from_slice(&chunk[..take]);
        }
        writer.write_all(chunk).await.map_err(internal)
    };

    let is_multipart = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().starts_with("multipart/form-data"));
    let name: Option<String>;
    let hidden_name: bool;
    if is_multipart {
        let mut multipart = Multipart::from_request(request, &())
            .await
            .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, "bad_request", e.body_text()))?;
        let mut found = None;
        while let Some(mut field) = multipart.next_field().await.map_err(multipart_error)? {
            if field.name() != Some("file") && field.file_name().is_none() {
                continue;
            }
            found = Some(field.file_name().map(str::to_string));
            while let Some(chunk) = field.chunk().await.map_err(multipart_error)? {
                write(&chunk).await?;
            }
            break;
        }
        let raw = found.ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "missing_file",
                "send the file in a form field named \"file\"",
            )
        })?;
        hidden_name = raw.as_deref().is_some_and(has_override);
        name = raw.as_deref().and_then(sanitize_filename);
    } else {
        let raw = request
            .uri()
            .query()
            .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("filename=")))
            .and_then(percent_decode);
        hidden_name = raw.as_deref().is_some_and(has_override);
        name = raw.as_deref().and_then(sanitize_filename);
        let mut body = request.into_body().into_data_stream();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|e| {
                ApiError::new(StatusCode::BAD_REQUEST, "bad_request", e.to_string())
            })?;
            write(&chunk).await?;
        }
    }
    writer.flush().await.map_err(internal)?;
    drop(writer);

    let mime = crate::policy::content_type(&head);
    Ok(Upload {
        file,
        size,
        sha256: hasher.finalize().into(),
        name,
        mime,
        hidden_name,
    })
}

/// Right-to-left overrides make `invoice\u{202e}fdp.exe` display as `invoiceexe.pdf`.
fn has_override(name: &str) -> bool {
    name.contains(['\u{202e}', '\u{202d}'])
}

fn multipart_error(err: axum::extract::multipart::MultipartError) -> ApiError {
    if err.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "file_too_large",
            err.body_text(),
        )
    } else {
        ApiError::new(StatusCode::BAD_REQUEST, "bad_request", err.body_text())
    }
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

async fn lookup_hash(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(sha256): Path<String>,
) -> Result<Json<ScanReport>, ApiError> {
    let mut digest = [0u8; 32];
    if sha256.len() != 64 || hex::decode_to_slice(&sha256, &mut digest).is_err() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_hash",
            "expected a SHA-256 in hexadecimal",
        ));
    }
    state.scanner.lookup(&digest).map(Json).ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "unknown_hash",
            "no verdict for this hash with the current signatures",
        )
    })
}

async fn status(State(state): State<AppState>, _auth: Authenticated) -> Json<serde_json::Value> {
    let scanner = &state.scanner;
    let settings = state.settings.get();
    let (scanning, queued) = scanner.in_flight();
    let malwarebazaar = match scanner.bazaar() {
        Some(b) => json!({ "status": "ready", "cached_hashes": b.cached_entries() }),
        None => json!({ "status": "disabled" }),
    };
    let (allowed, blocked) = state.hashlists.counts();
    Json(json!({
        "version": VERSION,
        "ready": scanner.not_ready_reason().is_none(),
        "started_at": state.started_at,
        "uptime_seconds": state.started.elapsed().as_secs(),
        "engines": {
            "clamav": scanner.clamav.state(),
            "yara": scanner.yara.state(),
            "malwarebazaar": malwarebazaar,
        },
        "scans": scanner.stats.snapshot(),
        "activity": { "scanning": scanning, "queued": queued },
        "limits": {
            "max_file_size": settings.limits.max_file_size,
            "max_concurrent_scans": state.cfg.max_concurrent_scans,
            "scan_timeout_seconds": settings.limits.scan_timeout_seconds,
            "cache_ttl_minutes": settings.limits.cache_ttl_minutes,
        },
        "protection": {
            "blocked_types": settings.policy.blocked,
            "disguised_files": settings.policy.disguised_files,
            "allowlist": allowed,
            "blocklist": blocked,
            "webhooks": settings.webhooks.len(),
            "dashboard_restricted": !settings.dashboard.allowed_networks.is_empty(),
        },
        "tls": *state.tls.read().unwrap(),
        "keys": state.keys.count(),
        "recent": scanner.stats.recent(),
    }))
}

async fn metrics(State(state): State<AppState>, _auth: Authenticated) -> Response {
    let scanner = &state.scanner;
    let clamav = scanner.clamav.state();
    let yara = scanner.yara.state();
    let daily_age = clamav.daily_built_at().map_or(-1.0, |built| {
        (time::OffsetDateTime::now_utc() - built).whole_seconds() as f64
    });
    let (scanning, queued) = scanner.in_flight();
    let body = scanner.stats.prometheus(&[
        (
            "filefender_ready",
            "1 when every enabled engine can scan.",
            f64::from(u8::from(scanner.not_ready_reason().is_none())),
        ),
        (
            "filefender_clamav_signatures",
            "Signatures loaded by ClamAV.",
            clamav.signatures as f64,
        ),
        (
            "filefender_clamav_daily_age_seconds",
            "Age of the ClamAV daily database.",
            daily_age,
        ),
        (
            "filefender_yara_rules",
            "YARA rules loaded.",
            yara.rules as f64,
        ),
        (
            "filefender_scans_in_progress",
            "Scans running now.",
            scanning as f64,
        ),
        (
            "filefender_scans_queued",
            "Requests waiting for a scan slot.",
            queued as f64,
        ),
    ]);
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_query_filenames() {
        assert_eq!(
            percent_decode("rapport%20final.pdf").as_deref(),
            Some("rapport final.pdf")
        );
        assert_eq!(percent_decode("a+b.txt").as_deref(), Some("a b.txt"));
        assert_eq!(percent_decode("%E2%9C%93.txt").as_deref(), Some("✓.txt"));
        assert_eq!(percent_decode("bad%2"), None);
        assert_eq!(percent_decode("bad%zz"), None);
    }

    #[test]
    fn ipv6_clients_are_grouped_by_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        assert_eq!(throttle_key(a), throttle_key(b));
        let v4: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(throttle_key(v4), v4);
    }
}
