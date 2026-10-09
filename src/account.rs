//! Dashboard access: the first visitor creates the first administrator; then each person signs
//! in with their own account (password, and a TOTP code when enabled). Roles limit what they do.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::api::{ApiError, AppState, ClientIp, check_throttle, record_failure};
use crate::users::{self, CreateError, Role, Session, SetupState, Totp, User};

const COOKIE: &str = "filefender_session";
/// Browsers cannot add this header to cross-site requests without CORS, which is never granted.
const CSRF_HEADER: &str = "x-filefender-csrf";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/setup", get(setup_status).post(setup))
        .route(
            "/v1/session",
            get(session_info).post(sign_in).delete(sign_out),
        )
        .route("/v1/keys", get(list_keys).post(create_key))
        .route("/v1/keys/{id}", delete(revoke_key).patch(restrict_key))
        .route("/v1/users", get(list_users).post(create_user))
        .route("/v1/users/{id}", patch(update_user).delete(delete_user))
        .route("/v1/account/password", post(change_password))
        .route("/v1/account/totp/setup", post(totp_setup))
        .route("/v1/account/totp/enable", post(totp_enable))
        .route("/v1/account/totp/disable", post(totp_disable))
}

fn require_csrf(headers: &HeaderMap) -> Result<(), ApiError> {
    if headers.contains_key(CSRF_HEADER) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "csrf",
            "missing the X-FileFender-CSRF header",
        ))
    }
}

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(COOKIE)?.strip_prefix('='))
        .filter(|token| !token.is_empty() && token.len() <= 128)
        .map(str::to_string)
}

fn set_cookie(state: &AppState, headers: &HeaderMap, token: &str) -> HeaderValue {
    let behind_https_proxy = state.cfg.trust_proxy_headers
        && headers
            .get("x-forwarded-proto")
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"https"));
    let secure = if state.cfg.tls() || behind_https_proxy {
        "; Secure"
    } else {
        ""
    };
    HeaderValue::from_str(&format!(
        "{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800{secure}"
    ))
    .expect("the token is base64url")
}

/// A signed-in person: their account as it is now in the store, and their session.
pub struct SignedIn {
    pub user: Arc<User>,
    session: Arc<Session>,
    token: String,
}

pub fn forbidden() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "forbidden",
        "your role does not allow this",
    )
}

impl SignedIn {
    fn at_least(self, role: Role) -> Result<Self, ApiError> {
        if self.user.role >= role {
            Ok(self)
        } else {
            Err(forbidden())
        }
    }
}

/// The signed-in account, if the request carries a valid session cookie.
pub fn dashboard_session(parts: &Parts, state: &AppState) -> Result<Option<SignedIn>, ApiError> {
    let Some(token) = session_cookie(&parts.headers) else {
        return Ok(None);
    };
    crate::api::require_dashboard_network(parts, state)?;
    let Some(session) = state.sessions.get(&token) else {
        return Ok(None);
    };
    let Some(user) = state
        .users
        .get(&session.user_id)
        .map_err(ApiError::internal)?
        .filter(|user| session.valid_for(user))
    else {
        return Ok(None);
    };
    if !matches!(parts.method, Method::GET | Method::HEAD) {
        require_csrf(&parts.headers)?;
    }
    Ok(Some(SignedIn {
        user,
        session,
        token,
    }))
}

impl FromRequestParts<AppState> for SignedIn {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        dashboard_session(parts, state)?.ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "session_required",
                "sign in to the dashboard",
            )
        })
    }
}

/// Operators and administrators: scans from the dashboard and the SHA-256 lists.
pub struct Operator(pub SignedIn);

impl FromRequestParts<AppState> for Operator {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        SignedIn::from_request_parts(parts, state)
            .await?
            .at_least(Role::Operator)
            .map(Operator)
    }
}

/// Administrators only: settings, API keys and accounts.
pub struct Administrator(pub SignedIn);

impl FromRequestParts<AppState> for Administrator {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        SignedIn::from_request_parts(parts, state)
            .await?
            .at_least(Role::Admin)
            .map(Administrator)
    }
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|err| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            format!("invalid JSON body: {err}"),
        )
    })
}

pub(crate) fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    parse(body)
}

fn invalid(message: &'static str) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid_input", message)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(ApiError::internal)
}

async fn hash(password: String) -> Result<String, ApiError> {
    blocking(move || users::hash_password(&password))
        .await?
        .map_err(ApiError::internal)
}

fn account(user: &User) -> Value {
    json!({
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "totp": user.totp.is_some(),
        "recovery_codes_left": user.recovery.len(),
    })
}

fn signed_in(state: &AppState, headers: &HeaderMap, user: &User, status: StatusCode) -> Response {
    let token = state.sessions.create(user);
    let mut response = (status, Json(account(user))).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, set_cookie(state, headers, &token));
    response
}

// ---------- first visit

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
    #[serde(default)]
    code: Option<String>,
}

async fn setup_status(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        match state.users.setup_state().map_err(ApiError::internal)? {
            SetupState::Done => json!({ "required": false, "open": false }),
            SetupState::Open { remaining } => json!({
                "required": true,
                "open": true,
                "remaining_seconds": remaining.map(|r| r.as_secs()),
            }),
            SetupState::Closed => json!({ "required": true, "open": false }),
        },
    ))
}

fn already_set_up() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "already_set_up",
        "the administrator account already exists",
    )
}

fn setup_closed() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "setup_closed",
        "the account creation window is over: restart FileFender to reopen it",
    )
}

async fn setup(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    require_csrf(&headers)?;
    let input: Credentials = parse(&body)?;
    let username = users::validate_username(&input.username).map_err(invalid)?;
    users::validate_password(&input.password, &username).map_err(invalid)?;
    match state.users.setup_state().map_err(ApiError::internal)? {
        SetupState::Done => return Err(already_set_up()),
        SetupState::Closed => return Err(setup_closed()),
        SetupState::Open { .. } => {}
    }
    let hash = hash(input.password).await?;
    let user = state
        .users
        .create_first(&username, hash)
        .map_err(|err| match err {
            CreateError::Exists | CreateError::Taken | CreateError::Full => already_set_up(),
            CreateError::Closed => setup_closed(),
            CreateError::Failed(err) => ApiError::internal(err),
        })?;
    state
        .audit
        .record("admin.created", &user.username, Some(ip), "");
    Ok(signed_in(&state, &headers, &user, StatusCode::CREATED))
}

// ---------- sign in and out

async fn session_info(session: SignedIn) -> Json<Value> {
    Json(account(&session.user))
}

async fn sign_in(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    require_csrf(&headers)?;
    check_throttle(&state, ip)?;
    let input: Credentials = parse(&body)?;
    if !matches!(
        state.users.setup_state().map_err(ApiError::internal)?,
        SetupState::Done
    ) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "setup_required",
            "create the administrator account first",
        ));
    }
    let found = state
        .users
        .by_username(&input.username)
        .map_err(ApiError::internal)?;
    // An unknown username is checked against a dummy hash: it takes as long as a wrong password.
    let stored = found.as_ref().map(|u| u.password.clone());
    let password = input.password;
    let password_ok = blocking(move || {
        let stored = stored.unwrap_or_else(|| (*users::DUMMY_HASH).clone());
        users::verify_password(&stored, &password)
    })
    .await?;
    let Some(user) = found.filter(|_| password_ok) else {
        record_failure(&state, ip);
        let tried: String = input.username.trim().chars().take(64).collect();
        state.audit.record(
            "session.failed",
            &tried,
            Some(ip),
            "wrong username or password",
        );
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "wrong username or password",
        ));
    };
    if user.totp.is_some() {
        let Some(code) = input.code.filter(|c| !c.trim().is_empty()) else {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "totp_required",
                "enter the code from your authenticator app",
            ));
        };
        match use_second_factor(&state, &user.id, &code)? {
            Some(true) => state.audit.record(
                "account.recovery_code_used",
                &user.username,
                Some(ip),
                format!(
                    "{} recovery codes left",
                    user.recovery.len().saturating_sub(1)
                ),
            ),
            Some(false) => {}
            None => {
                record_failure(&state, ip);
                state.audit.record(
                    "session.failed",
                    &user.username,
                    Some(ip),
                    "wrong two-factor code",
                );
                return Err(ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "invalid_code",
                    "this code is not valid",
                ));
            }
        }
    }
    let (user, ()) = state
        .users
        .modify(&user.id, |u| {
            u.last_sign_in = Some(crate::util::now_rfc3339());
            Some(())
        })
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::internal("the account disappeared during sign-in"))?;
    state
        .audit
        .record("session.signed_in", &user.username, Some(ip), "");
    Ok(signed_in(&state, &headers, &user, StatusCode::OK))
}

/// Accepts a TOTP code or an unused recovery code, each only once; `Some(true)` for a recovery
/// code.
fn use_second_factor(state: &AppState, id: &str, code: &str) -> Result<Option<bool>, ApiError> {
    let used = state
        .users
        .modify(id, |user| {
            let totp = user.totp.as_mut()?;
            let secret = hex::decode(&totp.secret).ok()?;
            if let Some(step) = users::totp_step(&secret, code, unix_now(), totp.last_step) {
                totp.last_step = step;
                return Some(false);
            }
            let hash = users::recovery_hash(code);
            let index = user.recovery.iter().position(|h| *h == hash)?;
            user.recovery.remove(index);
            Some(true)
        })
        .map_err(ApiError::internal)?;
    Ok(used.map(|(_, recovery)| recovery))
}

async fn sign_out(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    require_csrf(&headers)?;
    if let Some(token) = session_cookie(&headers) {
        let user = state
            .sessions
            .get(&token)
            .and_then(|session| state.users.get(&session.user_id).ok().flatten());
        if let Some(user) = user {
            state
                .audit
                .record("session.signed_out", &user.username, Some(ip), "");
        }
        state.sessions.remove(&token);
    }
    let clear = HeaderValue::from_static(
        "filefender_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
    );
    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, clear)]).into_response())
}

// ---------- API keys (administrators)

#[derive(Deserialize)]
struct NewKey {
    label: String,
}

async fn list_keys(
    State(state): State<AppState>,
    _admin: Administrator,
) -> Result<Json<Value>, ApiError> {
    let keys = crate::keys::list(&state.cfg.keys_file()).map_err(ApiError::internal)?;
    let keys: Vec<Value> = keys.iter().map(|k| key_json(&state, k)).collect();
    Ok(Json(json!({ "keys": keys })))
}

fn key_json(state: &AppState, key: &crate::keys::StoredKey) -> Value {
    let usage = state.keys.usage(&key.id);
    json!({
        "id": key.id,
        "label": key.label,
        "created_at": key.created_at,
        "allowed_networks": key.allowed_networks,
        "rate_per_minute": key.rate_per_minute,
        "expires_at": key.expires_at,
        "expired": key.expired(),
        "last_used_at": usage.last_used_at,
        "last_ip": usage.last_ip,
        "requests": usage.requests,
    })
}

async fn create_key(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Administrator(session): Administrator,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let input: NewKey = parse(&body)?;
    let (key, secret) =
        crate::keys::create(&state.cfg.keys_file(), &input.label).map_err(|err| {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_label", format!("{err:#}"))
        })?;
    state.keys.reload_if_changed();
    state.audit.record(
        "key.created",
        &session.user.username,
        Some(ip),
        format!("{} ({})", key.label, key.id),
    );
    let mut created = key_json(&state, &key);
    created["secret"] = json!(secret);
    Ok((StatusCode::CREATED, Json(created)))
}

async fn restrict_key(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Administrator(session): Administrator,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let input: crate::keys::Restrictions = parse(&body)?;
    let restrictions = input
        .validate()
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, "invalid_input", e))?;
    let summary = format!(
        "networks: {}; limit: {}; expires: {}",
        if restrictions.allowed_networks.is_empty() {
            "any".to_string()
        } else {
            restrictions.allowed_networks.join(" ")
        },
        restrictions
            .rate_per_minute
            .map_or("none".to_string(), |r| format!("{r}/min")),
        restrictions.expires_at.as_deref().unwrap_or("never"),
    );
    let key = crate::keys::restrict(&state.cfg.keys_file(), &id, restrictions)
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::new(StatusCode::NOT_FOUND, "unknown_key", "no key with this id")
        })?;
    state.keys.reload_if_changed();
    state.audit.record(
        "key.updated",
        &session.user.username,
        Some(ip),
        format!("{} ({}): {summary}", key.label, key.id),
    );
    Ok(Json(key_json(&state, &key)))
}

async fn revoke_key(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Administrator(session): Administrator,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let path = state.cfg.keys_file();
    let known = crate::keys::list(&path)
        .map_err(ApiError::internal)?
        .iter()
        .any(|k| k.id == id);
    if !known {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "unknown_key",
            "no key with this id",
        ));
    }
    let key = crate::keys::revoke(&path, &id).map_err(ApiError::internal)?;
    state.keys.reload_if_changed();
    state.audit.record(
        "key.revoked",
        &session.user.username,
        Some(ip),
        format!("{} ({})", key.label, key.id),
    );
    Ok(StatusCode::NO_CONTENT)
}

// ---------- accounts (administrators)

fn user_json(user: &User, me: &str) -> Value {
    json!({
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "totp": user.totp.is_some(),
        "created_at": user.created_at,
        "last_sign_in": user.last_sign_in,
        "me": user.id == me,
    })
}

fn unknown_user() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "unknown_user",
        "no account with this id",
    )
}

/// Administrators cannot lock themselves out: their own account changes on the Account page.
fn own_account() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "own_account",
        "change your own account on the Account page",
    )
}

async fn list_users(
    State(state): State<AppState>,
    Administrator(session): Administrator,
) -> Result<Json<Value>, ApiError> {
    let all = state.users.all().map_err(ApiError::internal)?;
    let list: Vec<Value> = all.iter().map(|u| user_json(u, &session.user.id)).collect();
    Ok(Json(json!({ "users": list })))
}

#[derive(Deserialize)]
struct NewUser {
    username: String,
    password: String,
    role: Role,
}

async fn create_user(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Administrator(session): Administrator,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let input: NewUser = parse(&body)?;
    let username = users::validate_username(&input.username).map_err(invalid)?;
    users::validate_password(&input.password, &username).map_err(invalid)?;
    let hash = hash(input.password).await?;
    let user = state
        .users
        .add(&username, input.role, hash)
        .map_err(|err| match err {
            CreateError::Taken => ApiError::new(
                StatusCode::CONFLICT,
                "username_taken",
                "this username is already used",
            ),
            CreateError::Full => ApiError::new(
                StatusCode::BAD_REQUEST,
                "too_many_accounts",
                "50 accounts at most",
            ),
            CreateError::Failed(err) => ApiError::internal(err),
            CreateError::Exists | CreateError::Closed => ApiError::internal("unexpected state"),
        })?;
    state.audit.record(
        "user.created",
        &session.user.username,
        Some(ip),
        format!("{} ({})", user.username, user.role.as_str()),
    );
    Ok((
        StatusCode::CREATED,
        Json(user_json(&user, &session.user.id)),
    ))
}

#[derive(Deserialize)]
struct UserChange {
    #[serde(default)]
    role: Option<Role>,
    /// A new password, given to the person; their sessions end.
    #[serde(default)]
    password: Option<String>,
    /// Turns two-factor authentication off, for a lost phone.
    #[serde(default)]
    reset_totp: bool,
}

async fn update_user(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Administrator(session): Administrator,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let input: UserChange = parse(&body)?;
    if id == session.user.id {
        return Err(own_account());
    }
    let before = state
        .users
        .get(&id)
        .map_err(ApiError::internal)?
        .ok_or_else(unknown_user)?;
    let password = match input.password {
        Some(password) => {
            users::validate_password(&password, &before.username).map_err(invalid)?;
            Some(hash(password).await?)
        }
        None => None,
    };
    let reset_password = password.is_some();
    let (user, ()) = state
        .users
        .modify(&id, |user| {
            if let Some(role) = input.role {
                user.role = role;
            }
            if let Some(hash) = password {
                user.password = hash;
                user.session_version = users::new_session_version();
            }
            if input.reset_totp {
                user.totp = None;
                user.recovery.clear();
            }
            Some(())
        })
        .map_err(ApiError::internal)?
        .ok_or_else(unknown_user)?;
    let by = &session.user.username;
    if user.role != before.role {
        state.audit.record(
            "user.role_changed",
            by,
            Some(ip),
            format!(
                "{}: {} -> {}",
                user.username,
                before.role.as_str(),
                user.role.as_str()
            ),
        );
    }
    if reset_password {
        state.audit.record(
            "user.password_reset",
            by,
            Some(ip),
            format!("{}: signed out", user.username),
        );
    }
    if input.reset_totp && before.totp.is_some() {
        state
            .audit
            .record("user.totp_reset", by, Some(ip), user.username.clone());
    }
    Ok(Json(user_json(&user, &session.user.id)))
}

async fn delete_user(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Administrator(session): Administrator,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if id == session.user.id {
        return Err(own_account());
    }
    let removed = state
        .users
        .remove(&id)
        .map_err(ApiError::internal)?
        .ok_or_else(unknown_user)?;
    state.audit.record(
        "user.deleted",
        &session.user.username,
        Some(ip),
        format!("{} ({})", removed.username, removed.role.as_str()),
    );
    Ok(StatusCode::NO_CONTENT)
}

// ---------- own account (every role)

#[derive(Deserialize)]
struct PasswordChange {
    current: String,
    new: String,
}

async fn check_password(
    state: &AppState,
    ip: std::net::IpAddr,
    user: &User,
    password: String,
) -> Result<(), ApiError> {
    check_throttle(state, ip)?;
    let stored = user.password.clone();
    if blocking(move || users::verify_password(&stored, &password)).await? {
        return Ok(());
    }
    record_failure(state, ip);
    Err(ApiError::new(
        StatusCode::FORBIDDEN,
        "wrong_password",
        "the current password is wrong",
    ))
}

async fn change_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: SignedIn,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let input: PasswordChange = parse(&body)?;
    check_password(&state, ip, &session.user, input.current).await?;
    users::validate_password(&input.new, &session.user.username).map_err(invalid)?;
    let hash = hash(input.new).await?;
    let (user, ()) = state
        .users
        .modify(&session.user.id, |user| {
            user.password = hash;
            user.session_version = users::new_session_version();
            Some(())
        })
        .map_err(ApiError::internal)?
        .ok_or_else(unknown_user)?;
    state.sessions.remove(&session.token);
    state.audit.record(
        "account.password_changed",
        &user.username,
        Some(ip),
        "other sessions signed out",
    );
    Ok(signed_in(&state, &headers, &user, StatusCode::OK))
}

async fn totp_setup(
    State(state): State<AppState>,
    session: SignedIn,
) -> Result<Json<Value>, ApiError> {
    if session.user.totp.is_some() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "totp_enabled",
            "two-factor authentication is already on",
        ));
    }
    let secret = users::new_totp_secret();
    *session.session.pending_totp.lock().unwrap() = Some(secret);
    let uri = users::otpauth_uri(&secret, &session.user.username, state.cfg.domain.as_deref());
    let qr = users::qr_rows(&uri).map_err(ApiError::internal)?;
    Ok(Json(
        json!({ "secret": users::base32(&secret), "uri": uri, "qr": qr }),
    ))
}

#[derive(Deserialize)]
struct Code {
    code: String,
}

fn invalid_code() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "invalid_code",
        "this code is not valid",
    )
}

async fn totp_enable(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: SignedIn,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    check_throttle(&state, ip)?;
    let input: Code = parse(&body)?;
    let Some(secret) = *session.session.pending_totp.lock().unwrap() else {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "totp_not_started",
            "start the two-factor setup first",
        ));
    };
    let Some(step) = users::totp_step(&secret, &input.code, unix_now(), 0) else {
        record_failure(&state, ip);
        return Err(invalid_code());
    };
    let (codes, hashes) = users::new_recovery_codes();
    state
        .users
        .modify(&session.user.id, |user| {
            if user.totp.is_some() {
                return None;
            }
            user.totp = Some(Totp {
                secret: hex::encode(secret),
                last_step: step,
            });
            user.recovery = hashes;
            Some(())
        })
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                "totp_enabled",
                "two-factor authentication is already on",
            )
        })?;
    *session.session.pending_totp.lock().unwrap() = None;
    state
        .audit
        .record("account.totp_enabled", &session.user.username, Some(ip), "");
    Ok(Json(json!({ "recovery_codes": codes })))
}

#[derive(Deserialize)]
struct Disable {
    password: String,
    code: String,
}

async fn totp_disable(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: SignedIn,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let input: Disable = parse(&body)?;
    check_password(&state, ip, &session.user, input.password).await?;
    let changed = state
        .users
        .modify(&session.user.id, |user| {
            let totp = user.totp.as_ref()?;
            let secret = hex::decode(&totp.secret).ok()?;
            let valid = users::totp_step(&secret, &input.code, unix_now(), totp.last_step)
                .is_some()
                || user.recovery.contains(&users::recovery_hash(&input.code));
            if !valid {
                return None;
            }
            user.totp = None;
            user.recovery.clear();
            Some(())
        })
        .map_err(ApiError::internal)?;
    let Some((user, ())) = changed else {
        record_failure(&state, ip);
        return Err(invalid_code());
    };
    state
        .audit
        .record("account.totp_disabled", &user.username, Some(ip), "");
    Ok(Json(account(&user)))
}
