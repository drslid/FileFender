//! Dashboard accounts: each person has an Argon2id password, optional TOTP and recovery codes,
//! and a role. The first visitor creates the first administrator. Sessions live in memory.

use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, anyhow};
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::util::{constant_time_eq, now_rfc3339, random_bytes};

pub const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_CHARS: usize = 256;
const MAX_ACCOUNTS: usize = 50;
const RECOVERY_CODES: usize = 8;
const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const TOTP_PERIOD: u64 = 30;

/// Ordered: each role can do everything the previous one can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Dashboard and activity.
    Viewer,
    /// Also scans files and manages the SHA-256 lists.
    Operator,
    /// Also settings, API keys and accounts.
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub role: Role,
    /// Argon2id hash in PHC format.
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<Totp>,
    /// SHA-256 of each unused recovery code.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery: Vec<String>,
    /// Sessions opened with another value are refused (password change or reset).
    pub session_version: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sign_in: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct UserFile {
    users: Vec<User>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Totp {
    /// Shared secret, hex encoded.
    pub secret: String,
    /// Last accepted time step: a code is never accepted twice.
    pub last_step: u64,
}

pub enum SetupState {
    Done,
    Open { remaining: Option<Duration> },
    Closed,
}

pub enum CreateError {
    Exists,
    Closed,
    Taken,
    Full,
    Failed(anyhow::Error),
}

type Stamp = (SystemTime, u64);

#[derive(Default)]
struct Cached {
    loaded: bool,
    stamp: Option<Stamp>,
    users: Arc<Vec<Arc<User>>>,
    empty_since: Option<Instant>,
}

/// `accounts.json`, re-read when it changes so that `filefender admin reset` applies at once.
pub struct UserStore {
    path: PathBuf,
    window: Option<Duration>,
    cached: RwLock<Cached>,
    write: Mutex<()>,
}

impl UserStore {
    pub fn open(path: &Path, window: Option<Duration>) -> Result<Self> {
        let store = UserStore {
            path: path.to_path_buf(),
            window,
            cached: RwLock::new(Cached::default()),
            write: Mutex::new(()),
        };
        store.refresh()?;
        Ok(store)
    }

    fn stamp(&self) -> Option<Stamp> {
        let meta = std::fs::metadata(&self.path).ok()?;
        Some((meta.modified().ok()?, meta.len()))
    }

    fn refresh(&self) -> Result<()> {
        let stamp = self.stamp();
        {
            let cached = self.cached.read().unwrap();
            if cached.loaded && cached.stamp == stamp {
                return Ok(());
            }
        }
        // An unreadable file must not reopen the account creation page.
        let users: Vec<Arc<User>> = match stamp {
            Some(_) => read(&self.path)?.into_iter().map(Arc::new).collect(),
            None => Vec::new(),
        };
        let mut cached = self.cached.write().unwrap();
        cached.empty_since = match (users.is_empty(), cached.empty_since) {
            (false, _) => None,
            (true, Some(since)) => Some(since),
            (true, None) => Some(Instant::now()),
        };
        cached.users = Arc::new(users);
        cached.stamp = stamp;
        cached.loaded = true;
        Ok(())
    }

    pub fn all(&self) -> Result<Arc<Vec<Arc<User>>>> {
        self.refresh()?;
        Ok(self.cached.read().unwrap().users.clone())
    }

    pub fn get(&self, id: &str) -> Result<Option<Arc<User>>> {
        Ok(self.all()?.iter().find(|u| u.id == id).cloned())
    }

    /// Usernames are unique whatever their case.
    pub fn by_username(&self, username: &str) -> Result<Option<Arc<User>>> {
        let wanted = username.trim().to_lowercase();
        Ok(self
            .all()?
            .iter()
            .find(|u| u.username.to_lowercase() == wanted)
            .cloned())
    }

    /// Until an account exists, the first visitor creates the administrator, within the window.
    pub fn setup_state(&self) -> Result<SetupState> {
        self.refresh()?;
        let cached = self.cached.read().unwrap();
        if !cached.users.is_empty() {
            return Ok(SetupState::Done);
        }
        let elapsed = cached.empty_since.map_or(Duration::ZERO, |s| s.elapsed());
        Ok(match self.window {
            None => SetupState::Open { remaining: None },
            Some(window) => match window.checked_sub(elapsed) {
                Some(remaining) if !remaining.is_zero() => SetupState::Open {
                    remaining: Some(remaining),
                },
                _ => SetupState::Closed,
            },
        })
    }

    fn new_user(username: &str, role: Role, password_hash: String) -> User {
        User {
            id: format!("usr_{}", hex::encode(random_bytes::<4>())),
            username: username.to_string(),
            role,
            password: password_hash,
            totp: None,
            recovery: Vec::new(),
            session_version: new_session_version(),
            created_at: now_rfc3339(),
            last_sign_in: None,
        }
    }

    /// The first account, an administrator, created on the setup page.
    pub fn create_first(
        &self,
        username: &str,
        password_hash: String,
    ) -> Result<Arc<User>, CreateError> {
        let _guard = self.write.lock().unwrap();
        match self.setup_state().map_err(CreateError::Failed)? {
            SetupState::Done => return Err(CreateError::Exists),
            SetupState::Closed => return Err(CreateError::Closed),
            SetupState::Open { .. } => {}
        }
        let mut user = Self::new_user(username, Role::Admin, password_hash);
        // The setup page signs its creator in.
        user.last_sign_in = Some(user.created_at.clone());
        self.save(vec![user.clone()]).map_err(CreateError::Failed)?;
        Ok(Arc::new(user))
    }

    /// An account added by an administrator.
    pub fn add(
        &self,
        username: &str,
        role: Role,
        password_hash: String,
    ) -> Result<Arc<User>, CreateError> {
        let _guard = self.write.lock().unwrap();
        let current = self.all().map_err(CreateError::Failed)?;
        let wanted = username.to_lowercase();
        if current.iter().any(|u| u.username.to_lowercase() == wanted) {
            return Err(CreateError::Taken);
        }
        if current.len() >= MAX_ACCOUNTS {
            return Err(CreateError::Full);
        }
        let user = Self::new_user(username, role, password_hash);
        let mut users: Vec<User> = current.iter().map(|u| (**u).clone()).collect();
        users.push(user.clone());
        self.save(users).map_err(CreateError::Failed)?;
        Ok(Arc::new(user))
    }

    /// Runs `change` on one account under the store lock; saves only when it returns `Some`.
    pub fn modify<R>(
        &self,
        id: &str,
        change: impl FnOnce(&mut User) -> Option<R>,
    ) -> Result<Option<(Arc<User>, R)>> {
        let _guard = self.write.lock().unwrap();
        let mut users: Vec<User> = self.all()?.iter().map(|u| (**u).clone()).collect();
        let Some(user) = users.iter_mut().find(|u| u.id == id) else {
            return Ok(None);
        };
        let Some(result) = change(user) else {
            return Ok(None);
        };
        let changed = Arc::new(user.clone());
        self.save(users)?;
        Ok(Some((changed, result)))
    }

    pub fn remove(&self, id: &str) -> Result<Option<Arc<User>>> {
        let _guard = self.write.lock().unwrap();
        let current = self.all()?;
        let Some(removed) = current.iter().find(|u| u.id == id).cloned() else {
            return Ok(None);
        };
        let users: Vec<User> = current
            .iter()
            .filter(|u| u.id != id)
            .map(|u| (**u).clone())
            .collect();
        self.save(users)?;
        Ok(Some(removed))
    }

    fn save(&self, users: Vec<User>) -> Result<()> {
        crate::util::write_private_json(&self.path, &UserFile { users })?;
        // Read back what was written: the cache always matches the file.
        let mut cached = self.cached.write().unwrap();
        cached.loaded = false;
        drop(cached);
        self.refresh()
    }

    /// Notices a reset within seconds, so that the setup window starts at the reset.
    pub async fn watch(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        loop {
            interval.tick().await;
            if let Err(err) = self.refresh() {
                tracing::error!("cannot read the dashboard accounts: {err:#}");
            }
        }
    }
}

pub fn read(path: &Path) -> Result<Vec<User>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<UserFile>(&bytes)
            .map(|file| file.users)
            .with_context(|| format!("{} is not a valid account file", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(err).with_context(|| format!("cannot read {}", path.display())),
    }
}

/// Deletes every account; returns whether there were any.
pub fn reset(path: &Path) -> Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("cannot delete {}", path.display())),
    }
}

pub fn new_session_version() -> String {
    hex::encode(random_bytes::<16>())
}

pub fn validate_username(name: &str) -> Result<String, &'static str> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err("the username must be 1 to 64 printable characters");
    }
    Ok(name.to_string())
}

pub fn validate_password(password: &str, username: &str) -> Result<(), &'static str> {
    let chars = password.chars().count();
    if chars < MIN_PASSWORD_CHARS {
        return Err("the password needs at least 12 characters");
    }
    if chars > MAX_PASSWORD_CHARS {
        return Err("the password is too long");
    }
    if password.trim().eq_ignore_ascii_case(username.trim()) {
        return Err("the password must differ from the username");
    }
    Ok(())
}

/// Argon2id with the OWASP parameters (19 MiB, 2 passes): about 50 ms, run it off the async threads.
pub fn hash_password(password: &str) -> Result<String> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|err| anyhow!("cannot hash the password: {err}"))
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    Argon2::default()
        .verify_password(password.as_bytes(), hash)
        .is_ok()
}

/// Checked when the username is unknown, so that it takes as long as a wrong password.
pub static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| hash_password("no such account, same delay").unwrap_or_default());

// ---------- TOTP (RFC 6238, the format every authenticator app reads)

pub fn new_totp_secret() -> [u8; 20] {
    random_bytes()
}

pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

pub fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC takes keys of any size");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let value = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    value % 1_000_000
}

/// The time step a 6-digit code belongs to, tolerating 30 s of clock drift; never a used step.
pub fn totp_step(secret: &[u8], code: &str, unix_seconds: u64, last_step: u64) -> Option<u64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = unix_seconds / TOTP_PERIOD;
    [now.saturating_sub(1), now, now + 1]
        .into_iter()
        .filter(|step| *step > last_step)
        .find(|step| {
            constant_time_eq(
                format!("{:06}", hotp(secret, *step)).as_bytes(),
                code.as_bytes(),
            )
        })
}

pub fn otpauth_uri(secret: &[u8], username: &str, domain: Option<&str>) -> String {
    let account = match domain {
        Some(domain) => format!("{username}@{domain}"),
        None => username.to_string(),
    };
    let encoded: String = account
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~@".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    format!(
        "otpauth://totp/FileFender:{encoded}?secret={}&issuer=FileFender&algorithm=SHA1&digits=6&period=30",
        base32(secret)
    )
}

/// QR code modules, one string of `0`/`1` per row, drawn by the dashboard.
pub fn qr_rows(data: &str) -> Result<Vec<String>> {
    let code = qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::M)
        .map_err(|err| anyhow!("cannot build the QR code: {err:?}"))?;
    let width = code.width();
    Ok(code
        .to_colors()
        .chunks(width)
        .map(|row| {
            row.iter()
                .map(|c| if *c == qrcode::Color::Dark { '1' } else { '0' })
                .collect()
        })
        .collect())
}

/// Returns the codes to show once and the hashes to store.
pub fn new_recovery_codes() -> (Vec<String>, Vec<String>) {
    (0..RECOVERY_CODES)
        .map(|_| {
            let raw = random_code(10);
            (format!("{}-{}", &raw[..5], &raw[5..]), recovery_hash(&raw))
        })
        .unzip()
}

fn random_code(len: usize) -> String {
    let limit = 256 - 256 % RECOVERY_ALPHABET.len();
    let mut code = String::with_capacity(len);
    while code.len() < len {
        let [byte] = random_bytes::<1>();
        if usize::from(byte) < limit {
            code.push(char::from(
                RECOVERY_ALPHABET[usize::from(byte) % RECOVERY_ALPHABET.len()],
            ));
        }
    }
    code
}

pub fn recovery_hash(code: &str) -> String {
    let normalized: String = code
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

// ---------- sessions

pub struct Session {
    pub user_id: String,
    version: String,
    /// Secret shown during two-factor enrollment, kept until the first code confirms it.
    pub pending_totp: Mutex<Option<[u8; 20]>>,
}

impl Session {
    /// Ends with a password change or reset, and with the account itself.
    pub fn valid_for(&self, user: &User) -> bool {
        self.user_id == user.id && self.version == user.session_version
    }
}

/// Dashboard sessions live in memory: a restart signs everyone out.
#[derive(Clone)]
pub struct Sessions {
    cache: moka::sync::Cache<[u8; 32], Arc<Session>>,
}

impl Default for Sessions {
    fn default() -> Self {
        Sessions {
            cache: moka::sync::Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(7 * 86_400))
                .time_to_idle(Duration::from_secs(12 * 3600))
                .build(),
        }
    }
}

impl Sessions {
    pub fn create(&self, user: &User) -> String {
        let token = URL_SAFE_NO_PAD.encode(random_bytes::<32>());
        self.cache.insert(
            token_id(&token),
            Arc::new(Session {
                user_id: user.id.clone(),
                version: user.session_version.clone(),
                pending_totp: Mutex::new(None),
            }),
        );
        token
    }

    pub fn get(&self, token: &str) -> Option<Arc<Session>> {
        self.cache.get(&token_id(token))
    }

    pub fn remove(&self, token: &str) {
        self.cache.invalidate(&token_id(token));
    }
}

fn token_id(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_matches_rfc_6238() {
        let secret = b"12345678901234567890";
        // RFC 6238 appendix B, SHA-1, last 6 of the 8 published digits.
        assert_eq!(hotp(secret, 59 / 30), 287_082);
        assert_eq!(hotp(secret, 1_111_111_109 / 30), 81_804);
        assert_eq!(totp_step(secret, "287082", 59, 0), Some(1));
        assert_eq!(
            totp_step(secret, "287 082", 59 + 30, 0),
            Some(1),
            "one step of drift"
        );
        assert_eq!(
            totp_step(secret, "287082", 59, 1),
            None,
            "a used step is refused"
        );
        assert_eq!(totp_step(secret, "287082", 59 + 90, 0), None);
        assert_eq!(totp_step(secret, "28708", 59, 0), None);
    }

    #[test]
    fn base32_follows_rfc_4648() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(&[0xff; 20]).len(), 32);
    }

    #[test]
    fn passwords_and_recovery_codes() {
        let hash = hash_password("correct horse battery").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(&hash, "correct horse battery"));
        assert!(!verify_password(&hash, "correct horse batterY"));
        assert!(validate_password("short", "admin").is_err());
        assert!(validate_password("administrator", "Administrator").is_err());
        assert!(validate_password("a long passphrase", "admin").is_ok());

        let (codes, hashes) = new_recovery_codes();
        assert_eq!(codes.len(), 8);
        assert!(
            codes
                .iter()
                .all(|c| c.len() == 11 && c.as_bytes()[5] == b'-')
        );
        assert_eq!(recovery_hash(&codes[0].to_lowercase()), hashes[0]);
    }

    #[test]
    fn setup_window_and_reset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.json");
        let store = UserStore::open(&path, Some(Duration::from_secs(60))).unwrap();
        assert!(matches!(
            store.setup_state().unwrap(),
            SetupState::Open { remaining: Some(_) }
        ));
        let first = store
            .create_first("admin", hash_password("a long passphrase").unwrap())
            .ok()
            .unwrap();
        assert_eq!(first.role, Role::Admin);
        assert!(matches!(store.setup_state().unwrap(), SetupState::Done));
        assert!(matches!(
            store.create_first("other", String::new()),
            Err(CreateError::Exists)
        ));
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&path).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);

        assert!(reset(&path).unwrap());
        assert!(matches!(
            store.setup_state().unwrap(),
            SetupState::Open { .. }
        ));

        let closed = UserStore::open(
            &dir.path().join("other.json"),
            Some(Duration::from_millis(1)),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(matches!(closed.setup_state().unwrap(), SetupState::Closed));
        assert!(matches!(
            closed.create_first("admin", String::new()),
            Err(CreateError::Closed)
        ));
    }

    #[test]
    fn accounts_are_added_changed_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.json");
        let store = UserStore::open(&path, None).unwrap();
        let admin = store.create_first("Alice", "hash".into()).ok().unwrap();
        let bob = store.add("bob", Role::Viewer, "hash".into()).ok().unwrap();
        assert!(matches!(
            store.add("ALICE", Role::Operator, String::new()),
            Err(CreateError::Taken)
        ));
        assert_eq!(store.by_username(" alice ").unwrap().unwrap().id, admin.id);
        assert!(Role::Viewer < Role::Operator && Role::Operator < Role::Admin);

        let (changed, ()) = store
            .modify(&bob.id, |u| {
                u.role = Role::Operator;
                Some(())
            })
            .unwrap()
            .unwrap();
        assert_eq!(changed.role, Role::Operator);
        assert!(store.modify("usr_missing", |_| Some(())).unwrap().is_none());

        let reopened = UserStore::open(&path, None).unwrap();
        assert_eq!(reopened.get(&bob.id).unwrap().unwrap().role, Role::Operator);
        assert_eq!(reopened.all().unwrap().len(), 2);
        assert_eq!(reopened.remove(&bob.id).unwrap().unwrap().username, "bob");
        assert!(reopened.remove(&bob.id).unwrap().is_none());
        assert_eq!(read(&path).unwrap().len(), 1);
    }

    #[test]
    fn corrupt_account_file_never_reopens_setup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.json");
        std::fs::write(&path, "{not json").unwrap();
        assert!(UserStore::open(&path, None).is_err());
    }
}
