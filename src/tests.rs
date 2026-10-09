//! End-to-end API tests against a mock clamd that receives the real file descriptor.

use std::fs::File;
use std::io::{IoSliceMut, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use crate::api::{self, AppState};
use crate::audit::Audit;
use crate::clamav::Clamav;
use crate::config::Config;
use crate::hashlist::HashLists;
use crate::keys::{self, KeyStore};
use crate::notify::Notifier;
use crate::scan::Scanner;
use crate::settings::{Settings, SettingsStore};
use crate::users::UserStore;
use crate::yara::Yara;

const BOUNDARY: &str = "FileFenderTestBoundary";

fn mock_clamd(dir: &Path) -> PathBuf {
    let path = dir.join("clamd.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || handle(stream));
        }
    });
    path
}

fn handle(mut stream: UnixStream) {
    let mut command = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte).unwrap_or(0) == 0 {
            return;
        }
        if byte[0] == 0 {
            break;
        }
        command.push(byte[0]);
    }
    let reply = match command.as_slice() {
        b"zPING" => "PONG".to_string(),
        b"zRELOAD" => "RELOADING".to_string(),
        b"zVERSION" => "ClamAV 1.5.4/27788/Wed Oct  8 07:52:03 2026".to_string(),
        b"zFILDES" => {
            let mut buf = [0u8; 1];
            let mut space = nix::cmsg_space!(RawFd);
            let mut iov = [IoSliceMut::new(&mut buf)];
            let message = recvmsg::<()>(
                stream.as_raw_fd(),
                &mut iov,
                Some(&mut space),
                MsgFlags::empty(),
            )
            .unwrap();
            let fd = message
                .cmsgs()
                .unwrap()
                .find_map(|c| match c {
                    ControlMessageOwned::ScmRights(fds) => fds.first().copied(),
                    _ => None,
                })
                .expect("no descriptor received");
            let mut file = unsafe { File::from_raw_fd(fd) };
            let mut content = Vec::new();
            file.read_to_end(&mut content).unwrap();
            let text = String::from_utf8_lossy(&content);
            if text.contains("EICAR-MOCK") {
                format!("fd[{fd}]: Win.Test.EICAR_HDB-1 FOUND")
            } else if text.contains("ENCRYPTED-MOCK") {
                format!("fd[{fd}]: Heuristics.Encrypted.Zip FOUND")
            } else if text.contains("ERROR-MOCK") {
                format!("fd[{fd}]: Can't allocate memory ERROR")
            } else {
                format!("fd[{fd}]: OK")
            }
        }
        _ => "UNKNOWN COMMAND".to_string(),
    };
    let _ = stream.write_all(format!("{reply}\0").as_bytes());
}

struct Harness {
    _dir: tempfile::TempDir,
    app: Router,
    key: String,
    state: AppState,
}

async fn harness(
    vars: &[(&str, &str)],
    yara_rules: Option<&str>,
    bazaar: Option<String>,
) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let mut all: Vec<(String, String)> = vec![
        (
            "FILEFENDER_DATA_DIR".into(),
            root.join("data").display().to_string(),
        ),
        (
            "FILEFENDER_TMP_DIR".into(),
            root.join("tmp").display().to_string(),
        ),
        (
            "FILEFENDER_RUN_DIR".into(),
            root.join("run").display().to_string(),
        ),
        ("FILEFENDER_YARA".into(), yara_rules.is_some().to_string()),
    ];
    all.extend(
        vars.iter()
            .map(|(k, v)| (format!("FILEFENDER_{k}"), v.to_string())),
    );
    let cfg = Arc::new(
        Config::from_lookup(|name| {
            all.iter()
                .rev()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        })
        .unwrap(),
    );
    crate::prepare_dirs(&cfg).unwrap();

    let (_, key) = keys::create(&cfg.keys_file(), "tests").unwrap();
    let keys = Arc::new(KeyStore::open(&cfg.keys_file()).unwrap());
    let http = crate::http_client().unwrap();
    let settings =
        Arc::new(SettingsStore::open(&cfg.settings_file(), Settings::from_config(&cfg)).unwrap());
    if bazaar.is_some() {
        let mut enabled = (*settings.get()).clone();
        enabled.malwarebazaar.enabled = true;
        enabled.malwarebazaar.auth_key = Some("test-auth-key-0123456789".into());
        settings.save(enabled).unwrap();
    }
    let hashlists = Arc::new(HashLists::open(&cfg.hashlist_file()).unwrap());
    let notifier = Notifier::start(settings.clone(), http.clone(), "tests".into());
    let audit = Arc::new(Audit::new(cfg.audit_file(), Some(notifier.clone())));
    let clamav = Arc::new(Clamav::with_socket(
        cfg.clone(),
        settings.clone(),
        mock_clamd(&root),
    ));
    clamav.refresh_version().await;
    let yara = Arc::new(Yara::new(cfg.clone(), settings.clone(), http.clone()));
    if let Some(rules) = yara_rules {
        yara.install_source("test-release", rules).unwrap();
    }
    let mut scanner = Scanner::new(cfg.clone(), settings, hashlists, clamav, yara, http);
    if let Some(endpoint) = bazaar {
        scanner = scanner.with_bazaar_endpoint(endpoint);
    }
    let users = Arc::new(UserStore::open(&cfg.accounts_file(), cfg.setup_window).unwrap());
    let state = AppState::new(cfg, keys, users, Arc::new(scanner), audit, notifier);
    Harness {
        _dir: dir,
        app: api::router(state.clone()),
        key,
        state,
    }
}

impl Harness {
    async fn send(&self, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, headers, json)
    }

    fn multipart(&self, name: &str, content: &[u8]) -> Request<Body> {
        let mut body = Vec::new();
        write!(
            body,
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n"
        )
        .unwrap();
        body.extend_from_slice(content);
        write!(body, "\r\n--{BOUNDARY}--\r\n").unwrap();
        Request::post("/v1/scan")
            .header("authorization", format!("Bearer {}", self.key))
            .header(
                "content-type",
                format!("multipart/form-data; boundary={BOUNDARY}"),
            )
            .body(Body::from(body))
            .unwrap()
    }

    fn raw(&self, query: &str, content: &'static [u8]) -> Request<Body> {
        Request::post(format!("/v1/scan{query}"))
            .header("x-api-key", &self.key)
            .header("content-type", "application/octet-stream")
            .body(Body::from(content))
            .unwrap()
    }

    fn get(&self, path: &str) -> Request<Body> {
        Request::get(path)
            .header("authorization", format!("Bearer {}", self.key))
            .body(Body::empty())
            .unwrap()
    }
}

const RULES: &str = r#"
    rule MAL_FileFender_Test {
        meta:
            description = "FileFender test marker"
            score = 85
        strings:
            $a = "YARA-MARKER"
        condition:
            $a
    }
"#;

#[tokio::test]
async fn clean_file_through_multipart() {
    let h = harness(&[], None, None).await;
    let content = b"just a harmless document";
    let (status, headers, body) = h.send(h.multipart("../report.pdf", content)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["verdict"], "clean");
    assert_eq!(body["file"]["name"], "report.pdf");
    assert_eq!(body["file"]["size"], content.len());
    assert_eq!(body["file"]["sha256"], hex::encode(Sha256::digest(content)));
    assert_eq!(body["engines"]["clamav"]["status"], "ok");
    assert_eq!(body["engines"]["clamav"]["version"], "1.5.4");
    assert_eq!(body["engines"]["yara"]["status"], "disabled");
    assert_eq!(body["threats"].as_array().unwrap().len(), 0);
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert!(
        headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    assert_eq!(headers["cache-control"], "no-store");
}

#[tokio::test]
async fn malicious_file_through_raw_body() {
    let h = harness(&[], None, None).await;
    let (status, _, body) = h
        .send(h.raw("?filename=inv%20oice.exe", b"MZ EICAR-MOCK"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["verdict"], "malicious");
    assert_eq!(body["file"]["name"], "inv oice.exe");
    assert_eq!(body["threats"][0]["engine"], "clamav");
    assert_eq!(body["threats"][0]["name"], "Win.Test.EICAR_HDB-1");
}

#[tokio::test]
async fn heuristics_are_suspicious_not_clean() {
    let h = harness(&[], None, None).await;
    let (status, _, body) = h.send(h.multipart("secret.zip", b"ENCRYPTED-MOCK")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["verdict"], "suspicious");
    assert_eq!(body["threats"][0]["severity"], "suspicious");
}

#[tokio::test]
async fn engine_errors_never_become_clean() {
    let h = harness(&[], None, None).await;
    let (status, _, body) = h.send(h.multipart("x.bin", b"ERROR-MOCK")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"]["code"], "scan_failed");
    assert!(body.get("verdict").is_none());
}

#[tokio::test]
async fn yara_matches_add_threats() {
    let h = harness(&[], Some(RULES), None).await;
    let (status, _, body) = h
        .send(h.multipart("tool.bin", b"payload YARA-MARKER"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["verdict"], "malicious");
    assert_eq!(body["threats"][0]["engine"], "yara");
    assert_eq!(body["threats"][0]["name"], "MAL_FileFender_Test");
    assert_eq!(body["threats"][0]["score"], 85);
    assert_eq!(body["engines"]["yara"]["status"], "ok");
}

#[tokio::test]
async fn low_yara_scores_are_suspicious() {
    let h = harness(&[("YARA_MALICIOUS_SCORE", "90")], Some(RULES), None).await;
    let (_, _, body) = h.send(h.multipart("tool.bin", b"YARA-MARKER")).await;
    assert_eq!(body["verdict"], "suspicious");
}

#[tokio::test]
async fn malwarebazaar_hits_are_malicious() {
    use axum::routing::post;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let known = hex::encode(Sha256::digest(b"known sample"));
    let api = Router::new().route(
        "/api/v1/",
        post(move |axum::Form(form): axum::Form<std::collections::HashMap<String, String>>| {
            let known = known.clone();
            async move {
                if form.get("hash") == Some(&known) {
                    axum::Json(serde_json::json!({"query_status": "ok", "data": [{"signature": "Remcos"}]}))
                } else {
                    axum::Json(serde_json::json!({"query_status": "hash_not_found"}))
                }
            }
        }),
    );
    tokio::spawn(axum::serve(listener, api).into_future());
    let h = harness(&[], None, Some(format!("http://{addr}/api/v1/"))).await;

    let (_, _, body) = h.send(h.multipart("a.exe", b"known sample")).await;
    assert_eq!(body["verdict"], "malicious", "{body}");
    assert_eq!(body["threats"][0]["engine"], "malwarebazaar");
    assert_eq!(body["threats"][0]["name"], "Remcos");
    let (_, _, body) = h.send(h.multipart("b.exe", b"unknown sample")).await;
    assert_eq!(body["verdict"], "clean");
    assert_eq!(body["engines"]["malwarebazaar"]["status"], "ok");
}

#[tokio::test]
async fn repeated_files_come_from_the_cache_and_hash_lookup() {
    let h = harness(&[], None, None).await;
    let (_, _, first) = h.send(h.multipart("a.txt", b"same content")).await;
    assert_eq!(first["cached"], false);
    let (_, _, second) = h.send(h.multipart("b.txt", b"same content")).await;
    assert_eq!(second["cached"], true);
    assert_eq!(second["file"]["name"], "b.txt");

    let sha = first["file"]["sha256"].as_str().unwrap();
    let (status, _, body) = h.send(h.get(&format!("/v1/hashes/{sha}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["verdict"], "clean");
    let (status, _, _) = h
        .send(h.get(&format!("/v1/hashes/{}", "0".repeat(64))))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = h.send(h.get("/v1/hashes/xyz")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn missing_and_invalid_keys_are_rejected_then_throttled() {
    let h = harness(&[], None, None).await;
    let anonymous = Request::post("/v1/scan").body(Body::from("x")).unwrap();
    let (status, headers, body) = h.send(anonymous).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.contains_key("www-authenticate"));
    assert_eq!(body["error"]["code"], "unauthorized");

    for _ in 0..20 {
        let wrong = Request::post("/v1/scan")
            .header("authorization", "Bearer ff_not-a-valid-key")
            .body(Body::from("x"))
            .unwrap();
        assert_eq!(h.send(wrong).await.0, StatusCode::UNAUTHORIZED);
    }
    let (status, headers, _) = h.send(h.multipart("a.txt", b"x")).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "even a valid key waits after repeated failures"
    );
    assert!(headers.contains_key("retry-after"));
}

#[tokio::test]
async fn oversized_uploads_are_refused() {
    let h = harness(&[("MAX_FILE_SIZE", "2K")], None, None).await;
    let (status, _, body) = h.send(h.multipart("big.bin", &[b'a'; 4096])).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"]["code"], "file_too_large");

    let declared = Request::post("/v1/scan")
        .header("authorization", format!("Bearer {}", h.key))
        .header("content-length", (64 * 1024 * 1024).to_string())
        .body(Body::empty())
        .unwrap();
    assert_eq!(h.send(declared).await.0, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn reload_waits_for_the_new_daily_version() {
    let h = harness(&[], None, None).await;
    let db = h.state.cfg.clamav_db_dir();
    std::fs::create_dir_all(&db).unwrap();
    let mut header =
        b"ClamAV-VDB:08 Oct 2026 07-52 -0400:27788:355740:90:x:y:builder:1791460320".to_vec();
    header.resize(512, b' ');
    std::fs::write(db.join("daily.cld"), &header).unwrap();

    h.state.scanner.clamav.reload().await.unwrap();
    let state = h.state.scanner.clamav.state();
    assert_eq!(state.status, crate::status::EngineStatus::Ready);
    assert!(
        state
            .databases
            .iter()
            .any(|d| d.name == "daily" && d.version == 27788)
    );
}

#[tokio::test]
async fn scans_wait_for_every_engine() {
    let h = harness(&[("YARA", "true")], None, None).await;
    let (status, _, _) = h
        .send(Request::get("/readyz").body(Body::empty()).unwrap())
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, headers, body) = h.send(h.multipart("a.txt", b"x")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "not_ready");
    assert!(headers.contains_key("retry-after"));
}

#[tokio::test]
async fn health_status_and_metrics() {
    let h = harness(&[], None, None).await;
    let (status, _, body) = h
        .send(Request::get("/healthz").body(Body::empty()).unwrap())
        .await;
    assert_eq!(
        (status, body["status"].as_str()),
        (StatusCode::OK, Some("ok"))
    );
    let (status, _, _) = h
        .send(Request::get("/readyz").body(Body::empty()).unwrap())
        .await;
    assert_eq!(status, StatusCode::OK);

    h.send(h.multipart("a.txt", b"EICAR-MOCK")).await;
    let (status, _, body) = h.send(h.get("/v1/status")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ready"], true);
    assert_eq!(body["scans"]["malicious"], 1);
    assert_eq!(body["recent"][0]["threat"], "Win.Test.EICAR_HDB-1");
    assert_eq!(body["engines"]["clamav"]["status"], "ready");
    assert_eq!(body["tls"]["mode"], "off");
    assert_eq!(
        h.send(Request::get("/v1/status").body(Body::empty()).unwrap())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    let response = h.app.clone().oneshot(h.get("/metrics")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let text = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        text.contains("filefender_scans_total{verdict=\"malicious\"} 1"),
        "{text}"
    );
    assert!(text.contains("filefender_ready 1"));
}

#[tokio::test]
async fn dashboard_is_served_with_versioned_assets() {
    let h = harness(&[], None, None).await;
    let response = h
        .app
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let tag = &*crate::web::ASSET_TAG;
    assert!(tag.len() == 12 && tag.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(html.contains(&format!("app.js?v={tag}")));
    assert!(html.contains(&format!("content=\"{}\"", api::VERSION)));
    assert!(!html.contains("{{"), "every placeholder is filled");
    let response = h
        .app
        .clone()
        .oneshot(Request::get("/assets/app.js").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["cache-control"]
            .to_str()
            .unwrap()
            .contains("immutable")
    );
    let (status, _, _) = h
        .send(
            Request::get("/assets/../keys.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let _ = &h.state;
}

// ---------- dashboard account

const PASSWORD: &str = "a long passphrase";

fn json_request(method: &str, path: &str, body: Value, cookie: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("x-filefender-csrf", "1");
    if let Some(cookie) = cookie {
        request = request.header("cookie", format!("theme=dark; filefender_session={cookie}"));
    }
    request.body(Body::from(body.to_string())).unwrap()
}

fn with_cookie(path: &str, cookie: &str) -> Request<Body> {
    Request::get(path)
        .header("cookie", format!("filefender_session={cookie}"))
        .body(Body::empty())
        .unwrap()
}

fn cookie_of(headers: &HeaderMap) -> String {
    let value = headers["set-cookie"].to_str().unwrap();
    let pair = value.split(';').next().unwrap();
    pair.strip_prefix("filefender_session=")
        .unwrap()
        .to_string()
}

impl Harness {
    async fn create_admin(&self) -> String {
        let body = json!({ "username": "admin", "password": PASSWORD });
        let (status, headers, body) = self
            .send(json_request("POST", "/v1/setup", body, None))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        cookie_of(&headers)
    }

    async fn sign_in(&self, password: &str, code: Option<&str>) -> (StatusCode, HeaderMap, Value) {
        let body = json!({ "username": "admin", "password": password, "code": code });
        self.send(json_request("POST", "/v1/session", body, None))
            .await
    }

    /// Signs in to another account and returns its session cookie.
    async fn session_of(&self, username: &str, password: &str) -> String {
        let body = json!({ "username": username, "password": password });
        let (status, headers, body) = self
            .send(json_request("POST", "/v1/session", body, None))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        cookie_of(&headers)
    }

    /// A file sent from the dashboard's Scan page.
    fn upload_as(&self, cookie: &str) -> Request<Body> {
        let mut upload = self.multipart("from-dashboard.txt", b"hello");
        let headers = upload.headers_mut();
        headers.remove("authorization");
        headers.insert(
            "cookie",
            format!("filefender_session={cookie}").parse().unwrap(),
        );
        headers.insert("x-filefender-csrf", "1".parse().unwrap());
        upload
    }
}

fn base32_decode(text: &str) -> Vec<u8> {
    let (mut out, mut buffer, mut bits) = (Vec::new(), 0u32, 0);
    for c in text.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("not base32"),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    out
}

fn current_code(secret: &[u8]) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{:06}", crate::users::hotp(secret, now / 30))
}

#[tokio::test]
async fn first_visitor_creates_the_administrator() {
    let h = harness(&[], None, None).await;
    let setup = || Request::get("/v1/setup").body(Body::empty()).unwrap();
    let (status, _, body) = h.send(setup()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (body["required"].as_bool(), body["open"].as_bool()),
        (Some(true), Some(true))
    );
    assert!(
        body["remaining_seconds"].as_u64().unwrap() > 1700,
        "30 minutes by default"
    );

    let forged = Request::post("/v1/setup")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "username": "admin", "password": PASSWORD }).to_string(),
        ))
        .unwrap();
    assert_eq!(
        h.send(forged).await.0,
        StatusCode::FORBIDDEN,
        "a cross-site form cannot create it"
    );
    let weak = json!({ "username": "admin", "password": "short" });
    let (status, _, body) = h.send(json_request("POST", "/v1/setup", weak, None)).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_input"))
    );

    let body = json!({ "username": " admin ", "password": PASSWORD });
    let (status, headers, body) = h.send(json_request("POST", "/v1/setup", body, None)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        (body["username"].as_str(), body["totp"].as_bool()),
        (Some("admin"), Some(false))
    );
    let set_cookie = headers["set-cookie"].to_str().unwrap();
    assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Strict"));
    assert!(
        !set_cookie.contains("Secure"),
        "plain HTTP behind a proxy or for local tests"
    );
    let cookie = cookie_of(&headers);
    let stored = std::fs::read_to_string(h.state.cfg.accounts_file()).unwrap();
    assert!(stored.contains("$argon2id$") && !stored.contains(PASSWORD));

    let second = json!({ "username": "mallory", "password": "another long passphrase" });
    let (status, _, body) = h
        .send(json_request("POST", "/v1/setup", second, None))
        .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::CONFLICT, Some("already_set_up"))
    );
    assert_eq!(h.send(setup()).await.2["required"], false);

    let (status, _, body) = h.send(with_cookie("/v1/session", &cookie)).await;
    assert_eq!(
        (status, body["username"].as_str()),
        (StatusCode::OK, Some("admin"))
    );
    assert_eq!(
        h.send(with_cookie("/v1/status", &cookie)).await.0,
        StatusCode::OK
    );

    let mut upload = h.multipart("from-dashboard.txt", b"hello");
    upload.headers_mut().remove("authorization");
    upload.headers_mut().insert(
        "cookie",
        format!("filefender_session={cookie}").parse().unwrap(),
    );
    let mut no_csrf = h.multipart("from-dashboard.txt", b"hello");
    *no_csrf.headers_mut() = upload.headers().clone();
    assert_eq!(
        h.send(no_csrf).await.0,
        StatusCode::FORBIDDEN,
        "uploads need the CSRF header"
    );
    upload
        .headers_mut()
        .insert("x-filefender-csrf", "1".parse().unwrap());
    let (status, _, body) = h.send(upload).await;
    assert_eq!(
        (status, body["verdict"].as_str()),
        (StatusCode::OK, Some("clean")),
        "{body}"
    );

    let (status, headers, _) = h
        .send(json_request(
            "DELETE",
            "/v1/session",
            json!({}),
            Some(&cookie),
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        headers["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(
        h.send(with_cookie("/v1/session", &cookie)).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn account_creation_closes_after_the_setup_window() {
    let h = harness(&[("SETUP_WINDOW", "1")], None, None).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, _, body) = h
        .send(Request::get("/v1/setup").body(Body::empty()).unwrap())
        .await;
    assert_eq!(
        (body["required"].as_bool(), body["open"].as_bool()),
        (Some(true), Some(false))
    );
    let body = json!({ "username": "admin", "password": PASSWORD });
    let (status, _, body) = h.send(json_request("POST", "/v1/setup", body, None)).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("setup_closed"))
    );
}

#[tokio::test]
async fn the_administrator_manages_api_keys() {
    let h = harness(&[], None, None).await;
    h.create_admin().await;
    let (status, _, body) = h.sign_in("wrong password!!", None).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_credentials"))
    );
    let (status, headers, _) = h.sign_in(PASSWORD, None).await;
    assert_eq!(status, StatusCode::OK);
    let cookie = cookie_of(&headers);

    assert_eq!(
        h.send(h.get("/v1/keys")).await.0,
        StatusCode::UNAUTHORIZED,
        "API keys cannot manage keys"
    );
    let forged = Request::post("/v1/keys")
        .header("cookie", format!("filefender_session={cookie}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({ "label": "x" }).to_string()))
        .unwrap();
    assert_eq!(h.send(forged).await.0, StatusCode::FORBIDDEN);

    let new = json!({ "label": "billing" });
    let (status, _, body) = h
        .send(json_request("POST", "/v1/keys", new.clone(), Some(&cookie)))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (id, secret) = (
        body["id"].as_str().unwrap().to_string(),
        body["secret"].as_str().unwrap().to_string(),
    );
    let (status, _, body) = h
        .send(json_request("POST", "/v1/keys", new, Some(&cookie)))
        .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_label"))
    );

    let scan_with = |key: &str| {
        Request::post("/v1/scan?filename=a.txt")
            .header("authorization", format!("Bearer {key}"))
            .body(Body::from("payload"))
            .unwrap()
    };
    assert_eq!(
        h.send(scan_with(&secret)).await.0,
        StatusCode::OK,
        "usable at once"
    );
    let (_, _, body) = h.send(with_cookie("/v1/keys", &cookie)).await;
    let labels: Vec<&str> = body["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["label"].as_str().unwrap())
        .collect();
    assert_eq!(labels, ["tests", "billing"]);
    assert!(
        !body.to_string().contains(&secret),
        "secrets are never listed"
    );

    let revoke = json_request(
        "DELETE",
        &format!("/v1/keys/{id}"),
        json!({}),
        Some(&cookie),
    );
    assert_eq!(h.send(revoke).await.0, StatusCode::NO_CONTENT);
    assert_eq!(
        h.send(scan_with(&secret)).await.0,
        StatusCode::UNAUTHORIZED,
        "refused at once"
    );
    let unknown = json_request("DELETE", "/v1/keys/key_00000000", json!({}), Some(&cookie));
    assert_eq!(h.send(unknown).await.0, StatusCode::NOT_FOUND);

    // Two failures so far: the wrong password and the revoked key.
    for _ in 0..18 {
        h.sign_in("wrong password!!", None).await;
    }
    let (status, headers, _) = h.sign_in(PASSWORD, None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.contains_key("retry-after"));
}

#[tokio::test]
async fn two_factor_authentication_with_recovery_codes() {
    let h = harness(&[("DOMAIN", "scan.example.com")], None, None).await;
    let cookie = h.create_admin().await;
    let (status, _, body) = h
        .send(json_request(
            "POST",
            "/v1/account/totp/setup",
            json!({}),
            Some(&cookie),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let uri = body["uri"].as_str().unwrap();
    assert!(
        uri.starts_with("otpauth://totp/FileFender:admin@scan.example.com?secret="),
        "{uri}"
    );
    assert!(body["qr"].as_array().unwrap().len() >= 21);
    let secret = base32_decode(body["secret"].as_str().unwrap());
    assert_eq!(secret.len(), 20);

    let code = current_code(&secret);
    let wrong = format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000);
    let enable = |code: &str| {
        json_request(
            "POST",
            "/v1/account/totp/enable",
            json!({ "code": code }),
            Some(&cookie),
        )
    };
    let (status, _, body) = h.send(enable(&wrong)).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_code"))
    );
    let (status, _, body) = h.send(enable(&code)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let recovery: Vec<String> = body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(recovery.len(), 8);
    assert_eq!(
        h.send(with_cookie("/v1/session", &cookie)).await.2["totp"],
        true
    );

    let (status, _, body) = h.sign_in(PASSWORD, None).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("totp_required"))
    );
    let (status, _, body) = h.sign_in(PASSWORD, Some(&code)).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_code")),
        "a code works once"
    );
    let (status, headers, body) = h.sign_in(PASSWORD, Some(&recovery[0].to_lowercase())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["recovery_codes_left"], 7);
    assert_eq!(
        h.sign_in(PASSWORD, Some(&recovery[0])).await.0,
        StatusCode::UNAUTHORIZED
    );

    let fresh = cookie_of(&headers);
    let disable = |password: &str, code: &str| {
        json_request(
            "POST",
            "/v1/account/totp/disable",
            json!({ "password": password, "code": code }),
            Some(&fresh),
        )
    };
    assert_eq!(
        h.send(disable("wrong password!!", &recovery[1])).await.0,
        StatusCode::FORBIDDEN
    );
    let (status, _, body) = h.send(disable(PASSWORD, &recovery[1])).await;
    assert_eq!(
        (status, body["totp"].as_bool()),
        (StatusCode::OK, Some(false)),
        "{body}"
    );
    assert_eq!(h.sign_in(PASSWORD, None).await.0, StatusCode::OK);
}

#[tokio::test]
async fn password_change_and_reset_sign_everyone_out() {
    let h = harness(&[], None, None).await;
    let first = h.create_admin().await;
    let second = cookie_of(&h.sign_in(PASSWORD, None).await.1);
    let change = |current: &str| {
        json_request(
            "POST",
            "/v1/account/password",
            json!({ "current": current, "new": "a brand new passphrase" }),
            Some(&second),
        )
    };
    let (status, _, body) = h.send(change("not the password")).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("wrong_password"))
    );
    let (status, headers, _) = h.send(change(PASSWORD)).await;
    assert_eq!(status, StatusCode::OK);
    let third = cookie_of(&headers);
    assert_eq!(
        h.send(with_cookie("/v1/session", &first)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h.send(with_cookie("/v1/session", &second)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h.send(with_cookie("/v1/session", &third)).await.0,
        StatusCode::OK
    );
    assert_eq!(h.sign_in(PASSWORD, None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h.sign_in("a brand new passphrase", None).await.0,
        StatusCode::OK
    );

    assert!(crate::users::reset(&h.state.cfg.accounts_file()).unwrap());
    assert_eq!(
        h.send(with_cookie("/v1/session", &third)).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (_, _, body) = h
        .send(Request::get("/v1/setup").body(Body::empty()).unwrap())
        .await;
    assert_eq!(
        (body["required"].as_bool(), body["open"].as_bool()),
        (Some(true), Some(true))
    );
    h.create_admin().await;
}

#[tokio::test]
async fn roles_decide_what_each_account_can_do() {
    let h = harness(&[], None, None).await;
    let admin = h.create_admin().await;
    let add = |username: &str, role: &str, cookie: &str| {
        json_request(
            "POST",
            "/v1/users",
            json!({ "username": username, "password": PASSWORD, "role": role }),
            Some(cookie),
        )
    };
    let (status, _, body) = h.send(add("olivia", "operator", &admin)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let olivia = body["id"].as_str().unwrap().to_string();
    let (status, _, body) = h.send(add("victor", "viewer", &admin)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let victor = body["id"].as_str().unwrap().to_string();
    let (status, _, body) = h.send(add("OLIVIA", "viewer", &admin)).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::CONFLICT, Some("username_taken"))
    );
    assert_eq!(
        h.send(add("eve", "root", &admin)).await.0,
        StatusCode::BAD_REQUEST
    );

    let operator = h.session_of("olivia", PASSWORD).await;
    let viewer = h.session_of("victor", PASSWORD).await;
    let (_, _, me) = h.send(with_cookie("/v1/session", &viewer)).await;
    assert_eq!(
        (me["username"].as_str(), me["role"].as_str()),
        (Some("victor"), Some("viewer"))
    );
    for cookie in [&operator, &viewer] {
        for path in ["/v1/status", "/v1/audit"] {
            assert_eq!(
                h.send(with_cookie(path, cookie)).await.0,
                StatusCode::OK,
                "{path}"
            );
        }
        for path in ["/v1/settings", "/v1/keys", "/v1/users"] {
            let (status, _, body) = h.send(with_cookie(path, cookie)).await;
            assert_eq!(
                (status, body["error"]["code"].as_str()),
                (StatusCode::FORBIDDEN, Some("forbidden")),
                "{path}"
            );
        }
    }
    assert_eq!(
        h.send(add("mallory", "admin", &operator)).await.0,
        StatusCode::FORBIDDEN
    );
    let block = |cookie: &str| {
        json_request(
            "POST",
            "/v1/hashlist",
            json!({ "sha256": "a".repeat(64), "list": "block" }),
            Some(cookie),
        )
    };
    assert_eq!(h.send(h.upload_as(&viewer)).await.0, StatusCode::FORBIDDEN);
    assert_eq!(h.send(block(&viewer)).await.0, StatusCode::FORBIDDEN);
    assert_eq!(
        h.send(with_cookie("/v1/hashlist", &viewer)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(h.send(h.upload_as(&operator)).await.0, StatusCode::OK);
    assert_eq!(h.send(block(&operator)).await.0, StatusCode::CREATED);

    let change = |id: &str, body: Value| {
        json_request("PATCH", &format!("/v1/users/{id}"), body, Some(&admin))
    };
    let (status, _, body) = h.send(change(&victor, json!({ "role": "operator" }))).await;
    assert_eq!(
        (status, body["role"].as_str()),
        (StatusCode::OK, Some("operator"))
    );
    assert_eq!(
        h.send(h.upload_as(&viewer)).await.0,
        StatusCode::OK,
        "a new role applies to open sessions"
    );

    let (_, _, body) = h.send(with_cookie("/v1/users", &admin)).await;
    assert_eq!(body["users"].as_array().unwrap().len(), 3);
    assert!(!body.to_string().contains("argon2"), "{body}");
    let me = body["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["me"] == true)
        .unwrap();
    assert_eq!(me["role"], "admin");
    let own = me["id"].as_str().unwrap();
    for request in [
        change(own, json!({ "role": "viewer" })),
        json_request(
            "DELETE",
            &format!("/v1/users/{own}"),
            json!({}),
            Some(&admin),
        ),
    ] {
        let (status, _, body) = h.send(request).await;
        assert_eq!(
            (status, body["error"]["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("own_account")),
            "the last administrator cannot remove himself"
        );
    }

    let reset = change(&olivia, json!({ "password": "another long passphrase" }));
    assert_eq!(h.send(reset).await.0, StatusCode::OK);
    assert_eq!(
        h.send(with_cookie("/v1/session", &operator)).await.0,
        StatusCode::UNAUTHORIZED,
        "a password reset signs the person out"
    );
    h.session_of("olivia", "another long passphrase").await;

    let delete = json_request(
        "DELETE",
        &format!("/v1/users/{victor}"),
        json!({}),
        Some(&admin),
    );
    assert_eq!(h.send(delete).await.0, StatusCode::NO_CONTENT);
    assert_eq!(
        h.send(with_cookie("/v1/session", &viewer)).await.0,
        StatusCode::UNAUTHORIZED
    );
    let again = json!({ "username": "victor", "password": PASSWORD });
    assert_eq!(
        h.send(json_request("POST", "/v1/session", again, None))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    let (_, _, body) = h.send(with_cookie("/v1/audit", &admin)).await;
    let actions: Vec<&str> = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    for expected in [
        "user.created",
        "user.role_changed",
        "user.password_reset",
        "user.deleted",
    ] {
        assert!(actions.contains(&expected), "{expected} in {actions:?}");
    }
}

#[tokio::test]
async fn generic_webhooks_get_a_signing_secret_shown_once() {
    let h = harness(&[], None, None).await;
    let cookie = h.create_admin().await;
    let (_, _, body) = h.send(with_cookie("/v1/settings", &cookie)).await;
    let mut settings = body["settings"].clone();
    settings["webhooks"] = json!([
        { "kind": "generic", "url": "https://example.com/hooks/filefender", "events": ["threats"] },
        { "kind": "slack", "url": "https://hooks.slack.com/services/x", "events": ["threats"] },
    ]);
    let put =
        |settings: &Value| json_request("PUT", "/v1/settings", settings.clone(), Some(&cookie));
    let stored = || h.state.settings.get().webhooks[0].secret.clone();

    let (status, _, body) = h.send(put(&settings)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let saved = body["settings"].clone();
    let id = saved["webhooks"][0]["id"].as_str().unwrap().to_string();
    let secret = body["new_secrets"][&id].as_str().unwrap().to_string();
    assert!(crate::notify::valid_signing_secret(&secret), "{secret}");
    assert_eq!(
        body["new_secrets"].as_object().unwrap().len(),
        1,
        "only generic webhooks are signed"
    );
    assert_eq!(saved["webhooks"][0]["secret"], Value::Null);
    assert_eq!(saved["webhooks"][0]["secret_set"], true);
    assert_eq!(saved["webhooks"][1]["secret_set"], false);
    assert_eq!(stored().as_deref(), Some(secret.as_str()));

    let (_, _, body) = h.send(put(&saved)).await;
    assert_eq!(body["new_secrets"], json!({}));
    assert!(!body.to_string().contains(&secret), "shown once");
    assert_eq!(stored().as_deref(), Some(secret.as_str()));

    let mut forged = saved.clone();
    forged["webhooks"][0]["secret"] = json!(crate::notify::new_signing_secret());
    assert_eq!(h.send(put(&forged)).await.0, StatusCode::OK);
    assert_eq!(
        stored().as_deref(),
        Some(secret.as_str()),
        "the browser cannot choose the secret"
    );

    let mut rotate = saved.clone();
    rotate["webhooks"][0]["rotate_secret"] = json!(true);
    let (_, _, body) = h.send(put(&rotate)).await;
    let rotated = body["new_secrets"][&id].as_str().unwrap().to_string();
    assert_ne!(rotated, secret);
    assert_eq!(stored(), Some(rotated));
}

// ---------- settings, lists, policy, key restrictions and alerts

impl Harness {
    fn apply(&self, change: impl FnOnce(&mut Settings)) {
        let mut settings = (*self.state.settings.get()).clone();
        change(&mut settings);
        self.state.settings.save(settings).unwrap();
    }

    async fn ready(&self) -> StatusCode {
        self.send(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .0
    }
}

fn fake_program() -> Vec<u8> {
    let mut program = vec![0u8; 0x80];
    program[..2].copy_from_slice(b"MZ");
    program[0x3c] = 0x40;
    program[0x40..0x44].copy_from_slice(b"PE\0\0");
    program
}

#[tokio::test]
async fn settings_are_edited_from_the_dashboard_without_leaking_secrets() {
    let h = harness(&[], None, None).await;
    let cookie = h.create_admin().await;
    assert_eq!(
        h.send(h.get("/v1/settings")).await.0,
        StatusCode::UNAUTHORIZED,
        "API keys cannot read the settings"
    );

    let (status, _, body) = h.send(with_cookie("/v1/settings", &cookie)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["catalog"]["feeds"].as_array().unwrap().len(), 6);
    let mut settings = body["settings"].clone();
    assert_eq!(settings["clamav"]["max_recursion"], 17);
    settings["clamav"]["detect_pua"] = json!(true);
    settings["feeds"] = json!(["urlhaus"]);
    settings["malwarebazaar"]["enabled"] = json!(true);
    settings["malwarebazaar"]["auth_key"] = json!("abcdef0123456789abcdef0123456789");
    settings["webhooks"] = json!([{
        "kind": "discord",
        "url": "https://discord.com/api/webhooks/1/hidden-token",
        "events": ["threats"],
    }]);
    let (status, _, body) = h
        .send(json_request("PUT", "/v1/settings", settings, Some(&cookie)))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let saved = body["settings"].clone();
    assert_eq!(saved["malwarebazaar"]["auth_key"], Value::Null);
    assert_eq!(saved["malwarebazaar"]["auth_key_set"], true);
    assert_eq!(saved["webhooks"][0]["url"], Value::Null);
    assert_eq!(saved["webhooks"][0]["url_hint"], "discord.com/…");
    let text = body.to_string();
    assert!(!text.contains("hidden-token") && !text.contains("abcdef0123"));
    let id = saved["webhooks"][0]["id"].as_str().unwrap().to_string();

    // The masked form sent back keeps the secrets.
    let mut again = saved.clone();
    again["clamav"]["max_recursion"] = json!(10);
    let (status, _, body) = h
        .send(json_request("PUT", "/v1/settings", again, Some(&cookie)))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let current = h.state.settings.get();
    assert_eq!(current.clamav.max_recursion, 10);
    assert!(current.clamav.detect_pua);
    assert_eq!(
        current.malwarebazaar.auth_key.as_deref(),
        Some("abcdef0123456789abcdef0123456789")
    );
    assert_eq!(
        current.webhooks[0].url,
        "https://discord.com/api/webhooks/1/hidden-token"
    );
    assert_eq!(current.webhooks[0].id, id);
    let on_disk = std::fs::read_to_string(h.state.cfg.settings_file()).unwrap();
    assert!(on_disk.contains("\"detect_pua\": true"));

    let mut invalid = saved.clone();
    invalid["limits"]["scan_timeout_seconds"] = json!(1);
    let (status, _, body) = h
        .send(json_request("PUT", "/v1/settings", invalid, Some(&cookie)))
        .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_settings"))
    );
    let mut lockout = saved.clone();
    lockout["dashboard"]["allowed_networks"] = json!(["192.0.2.0/24"]);
    let (status, _, body) = h
        .send(json_request("PUT", "/v1/settings", lockout, Some(&cookie)))
        .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("lockout")),
        "an administrator cannot lock himself out"
    );

    let (status, _, body) = h.send(with_cookie("/v1/audit", &cookie)).await;
    assert_eq!(status, StatusCode::OK);
    let actions: Vec<&str> = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions[..2], ["settings.updated", "settings.updated"]);
    assert!(actions.contains(&"admin.created"));
    assert!(!body.to_string().contains("hidden-token"));
}

#[tokio::test]
async fn the_dashboard_answers_only_allowed_networks() {
    let h = harness(&[], None, None).await;
    let cookie = h.create_admin().await;
    h.apply(|s| s.dashboard.allowed_networks = vec!["192.0.2.0/24".into()]);
    let (status, _, body) = h.send(Request::get("/").body(Body::empty()).unwrap()).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("dashboard_forbidden"))
    );
    for path in ["/v1/session", "/v1/settings", "/v1/status"] {
        assert_eq!(
            h.send(with_cookie(path, &cookie)).await.0,
            StatusCode::FORBIDDEN,
            "{path} with the session cookie"
        );
    }
    assert_eq!(
        h.send(h.get("/v1/status")).await.0,
        StatusCode::OK,
        "API keys are not affected"
    );

    // `filefender admin unlock-dashboard` clears the list on disk.
    let file = h.state.cfg.settings_file();
    let defaults = Settings::from_config(&h.state.cfg);
    crate::settings::edit_file(&file, defaults.clone(), |s| {
        s.dashboard.allowed_networks.clear()
    })
    .unwrap();
    let reopened = SettingsStore::open(&file, defaults).unwrap();
    assert!(reopened.get().dashboard.allowed_networks.is_empty());
}

#[tokio::test]
async fn sha256_lists_decide_before_the_engines() {
    let h = harness(&[], None, None).await;
    let cookie = h.create_admin().await;
    let add = |sha: &str, list: &str, note: &str| {
        json_request(
            "POST",
            "/v1/hashlist",
            json!({ "sha256": sha, "list": list, "note": note }),
            Some(&cookie),
        )
    };
    let flagged = b"EICAR-MOCK in a vendor tool";
    let flagged_sha = hex::encode(Sha256::digest(flagged));
    let (status, _, body) = h.send(add(&flagged_sha, "allow", "vendor tool")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (_, _, body) = h.send(h.multipart("tool.exe", flagged)).await;
    assert_eq!(body["verdict"], "clean", "{body}");
    assert_eq!(body["listed"], "allowlist");
    assert_eq!(body["engines"]["clamav"]["status"], "skipped");

    let sample = b"incident sample";
    let sample_sha = hex::encode(Sha256::digest(sample));
    h.send(add(&sample_sha, "block", "INC-42")).await;
    let (_, _, body) = h.send(h.multipart("a.txt", sample)).await;
    assert_eq!(body["verdict"], "malicious");
    assert_eq!(body["threats"][0]["engine"], "blocklist");
    assert_eq!(body["threats"][0]["description"], "INC-42");
    let (status, _, body) = h.send(h.get(&format!("/v1/hashes/{sample_sha}"))).await;
    assert_eq!(
        (status, body["listed"].as_str()),
        (StatusCode::OK, Some("blocklist"))
    );
    assert!(body["file"].get("size").is_none());

    let (_, _, body) = h.send(with_cookie("/v1/hashlist", &cookie)).await;
    assert_eq!(
        (body["allow"].as_u64(), body["block"].as_u64()),
        (Some(1), Some(1))
    );
    let remove = json_request(
        "DELETE",
        &format!("/v1/hashlist/{flagged_sha}"),
        Value::Null,
        Some(&cookie),
    );
    assert_eq!(h.send(remove).await.0, StatusCode::NO_CONTENT);
    let (_, _, body) = h.send(h.multipart("tool.exe", flagged)).await;
    assert_eq!(body["verdict"], "malicious");

    let by_key = Request::post("/v1/hashlist")
        .header("authorization", format!("Bearer {}", h.key))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "sha256": flagged_sha, "list": "allow" }).to_string(),
        ))
        .unwrap();
    assert_eq!(
        h.send(by_key).await.0,
        StatusCode::UNAUTHORIZED,
        "only the administrator edits the lists"
    );
}

#[tokio::test]
async fn the_file_policy_refuses_types_and_disguises() {
    let h = harness(&[], None, None).await;
    let (_, _, body) = h.send(h.multipart("holiday.jpg", &fake_program())).await;
    assert_eq!(body["verdict"], "malicious", "{body}");
    assert_eq!(body["threats"][0]["name"], "Policy.Disguised.Executable");
    assert_eq!(
        body["file"]["type"],
        "application/vnd.microsoft.portable-executable"
    );
    let (_, _, body) = h
        .send(h.multipart("notes.txt", b"MZ is just how this text starts"))
        .await;
    assert_eq!(body["verdict"], "clean", "{body}");
    let (_, _, body) = h
        .send(h.raw("?filename=invoice%E2%80%AEfdp.exe", b"plain"))
        .await;
    assert_eq!(body["threats"][0]["name"], "Policy.Disguised.Name");
    assert_eq!(body["file"]["name"], "invoicefdp.exe");

    // The policy follows the name, even when the engines' verdict comes from the cache.
    h.apply(|s| s.policy.blocked = vec!["archives".into()]);
    let (_, _, blocked) = h.send(h.multipart("backup.zip", b"same bytes")).await;
    assert_eq!(blocked["threats"][0]["name"], "Policy.Blocked.Archives");
    let (_, _, renamed) = h.send(h.multipart("backup.txt", b"same bytes")).await;
    assert_eq!(
        (renamed["verdict"].as_str(), renamed["cached"].as_bool()),
        (Some("clean"), Some(true))
    );

    h.apply(|s| {
        s.policy.blocked.clear();
        s.policy.disguised_files = false;
    });
    let (_, _, body) = h.send(h.multipart("holiday.jpg", &fake_program())).await;
    assert_eq!(body["verdict"], "clean");
    assert_eq!(body["engines"]["policy"]["status"], "disabled");
}

#[tokio::test]
async fn api_keys_can_be_restricted() {
    let h = harness(&[], None, None).await;
    let cookie = h.create_admin().await;
    let (_, _, body) = h.send(with_cookie("/v1/keys", &cookie)).await;
    let id = body["keys"][0]["id"].as_str().unwrap().to_string();
    let restrict =
        |body: Value| json_request("PATCH", &format!("/v1/keys/{id}"), body, Some(&cookie));
    let error = |body: &Value| body["error"]["code"].as_str().map(str::to_string);

    let (status, _, body) = h
        .send(restrict(json!({ "allowed_networks": ["192.0.2.0/24"] })))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, body) = h.send(h.get("/v1/status")).await;
    assert_eq!(
        (status, error(&body).as_deref()),
        (StatusCode::FORBIDDEN, Some("ip_not_allowed"))
    );

    h.send(restrict(json!({ "rate_per_minute": 2 }))).await;
    assert_eq!(h.send(h.get("/v1/status")).await.0, StatusCode::OK);
    assert_eq!(h.send(h.get("/v1/status")).await.0, StatusCode::OK);
    let (status, headers, body) = h.send(h.get("/v1/status")).await;
    assert_eq!(
        (status, error(&body).as_deref()),
        (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited"))
    );
    assert!(headers.contains_key("retry-after"));

    h.send(restrict(json!({ "expires_at": "2020-01-01T00:00:00Z" })))
        .await;
    let (status, _, body) = h.send(h.get("/v1/status")).await;
    assert_eq!(
        (status, error(&body).as_deref()),
        (StatusCode::UNAUTHORIZED, Some("key_expired"))
    );

    let (status, _, _) = h.send(restrict(json!({ "rate_per_minute": 0 }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    h.send(restrict(json!({}))).await;
    assert_eq!(
        h.send(h.get("/v1/status")).await.0,
        StatusCode::OK,
        "restrictions removed"
    );
    let (_, _, body) = h.send(with_cookie("/v1/keys", &cookie)).await;
    assert_eq!(body["keys"][0]["requests"], 3);
    assert!(body["keys"][0]["last_used_at"].is_string());
    assert_eq!(body["keys"][0]["expired"], false);
}

#[tokio::test]
async fn threats_are_sent_to_webhooks_once_per_file() {
    use axum::body::Bytes;
    use axum::routing::post;
    use hmac::{Hmac, KeyInit, Mac};
    let (sender, mut received) = tokio::sync::mpsc::unbounded_channel::<(HeaderMap, Bytes)>();
    let hook = Router::new().route(
        "/hook",
        post(move |headers: HeaderMap, body: Bytes| {
            let sender = sender.clone();
            async move {
                sender.send((headers, body)).ok();
                StatusCode::NO_CONTENT
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, hook).into_future());

    let h = harness(&[], None, None).await;
    let secret = crate::notify::new_signing_secret();
    let mut settings = (*h.state.settings.get()).clone();
    settings.webhooks.push(crate::settings::Webhook {
        id: "wh_test".into(),
        kind: "generic".into(),
        url: format!("http://{addr}/hook"),
        events: vec!["threats".into()],
        secret: Some(secret.clone()),
    });
    h.state.settings.force(settings);

    h.send(h.multipart("invoice.exe", b"EICAR-MOCK")).await;
    h.send(h.multipart("copy.exe", b"EICAR-MOCK")).await;
    let ms = std::time::Duration::from_millis;
    let (headers, raw) = tokio::time::timeout(ms(5000), received.recv())
        .await
        .expect("no alert")
        .unwrap();
    let alert: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(alert["event"], "threats");
    assert_eq!(alert["level"], "critical");
    assert_eq!(alert["title"], "Malicious file: invoice.exe");
    assert_eq!(alert["data"]["threats"][0]["name"], "Win.Test.EICAR_HDB-1");
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(headers["x-filefender-event"], "threats");

    // What a receiver does: HMAC of "<t>.<raw body>", and a recent timestamp.
    let signature = headers["x-filefender-signature"].to_str().unwrap();
    let (t, v1) = signature
        .strip_prefix("t=")
        .and_then(|rest| rest.split_once(",v1="))
        .expect("t=<unix>,v1=<hex>");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(now.abs_diff(t.parse().unwrap()) < 60);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{t}.").as_bytes());
    mac.update(&raw);
    mac.verify_slice(&hex::decode(v1).unwrap())
        .expect("valid signature");

    assert!(
        tokio::time::timeout(ms(500), received.recv())
            .await
            .is_err(),
        "the same file is announced once an hour"
    );
    h.send(h.multipart("clean.txt", b"harmless")).await;
    assert!(
        tokio::time::timeout(ms(300), received.recv())
            .await
            .is_err(),
        "clean files are not announced"
    );
}

#[tokio::test]
async fn engines_and_limits_follow_the_saved_settings() {
    let h = harness(&[("YARA", "true")], None, None).await;
    assert_eq!(h.ready().await, StatusCode::SERVICE_UNAVAILABLE);
    h.apply(|s| s.yara.enabled = false);
    assert_eq!(h.ready().await, StatusCode::OK, "YARA turned off");

    h.apply(|s| {
        s.limits.cache_ttl_minutes = 0;
        s.limits.max_file_size = 2048;
    });
    let (_, _, first) = h.send(h.multipart("a.txt", b"same")).await;
    let (_, _, second) = h.send(h.multipart("a.txt", b"same")).await;
    assert_eq!(
        (first["cached"].as_bool(), second["cached"].as_bool()),
        (Some(false), Some(false)),
        "cache turned off"
    );
    assert_eq!(
        h.send(h.multipart("big.bin", &[b'a'; 4096])).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let (_, _, status) = h.send(h.get("/v1/status")).await;
    assert_eq!(status["limits"]["max_file_size"], 2048);

    let h = harness(&[], Some(RULES), None).await;
    let (_, _, body) = h.send(h.multipart("tool.bin", b"YARA-MARKER")).await;
    assert_eq!(body["verdict"], "malicious");
    h.apply(|s| s.yara.enabled = false);
    let (_, _, body) = h.send(h.multipart("tool.bin", b"YARA-MARKER")).await;
    assert_eq!(body["verdict"], "clean", "{body}");
    assert_eq!(body["engines"]["yara"]["status"], "disabled");
}
