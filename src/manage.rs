//! Dashboard endpoints beyond the account: settings, update now and webhook tests
//! (administrators), SHA-256 lists (operators), activity log (everyone signed in).

use std::collections::BTreeMap;
use std::net::IpAddr;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::account::{Administrator, Operator, SignedIn, parse_json};
use crate::api::{ApiError, AppState, ClientIp};
use crate::clamav::feeds::FEEDS;
use crate::hashlist::{HashEntry, ListKind};
use crate::notify::{Alert, Event, Level};
use crate::settings::{
    POLICY_CATEGORIES, Settings, WEBHOOK_EVENTS, WEBHOOK_KINDS, Webhook, YARA_PACKAGES,
    networks_allow,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/settings", get(get_settings).put(put_settings))
        .route("/v1/settings/update", post(update_now))
        .route("/v1/webhooks/test", post(test_webhook))
        .route("/v1/hashlist", get(list_hashes).post(add_hash))
        .route("/v1/hashlist/{sha256}", delete(remove_hash))
        .route("/v1/audit", get(audit_log))
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid_settings", message)
}

/// Webhook URLs usually embed a secret: only the host is shown again.
fn url_hint(url: &str) -> String {
    let rest = url.strip_prefix("https://").unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = host.rsplit('@').next().unwrap_or(host);
    format!("{host}/…")
}

fn masked(settings: &Settings) -> Value {
    let mut value = serde_json::to_value(settings).unwrap_or_default();
    value["malwarebazaar"]["auth_key_set"] = json!(settings.malwarebazaar.auth_key.is_some());
    value["malwarebazaar"]["auth_key"] = Value::Null;
    if let Some(hooks) = value["webhooks"].as_array_mut() {
        for (hook, saved) in hooks.iter_mut().zip(&settings.webhooks) {
            hook["url_hint"] = json!(url_hint(&saved.url));
            hook["url"] = Value::Null;
            hook["secret_set"] = json!(saved.secret.is_some());
            hook["secret"] = Value::Null;
        }
    }
    value
}

fn settings_payload(state: &AppState, ip: IpAddr) -> Value {
    let feeds: Vec<Value> = FEEDS
        .iter()
        .map(|f| {
            json!({
                "id": f.id,
                "provider": f.provider,
                "homepage": f.homepage,
                "files": f.files().collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "settings": masked(&state.settings.get()),
        "catalog": {
            "feeds": feeds,
            "policy_categories": POLICY_CATEGORIES,
            "webhook_kinds": WEBHOOK_KINDS,
            "webhook_events": WEBHOOK_EVENTS,
            "yara_packages": YARA_PACKAGES,
        },
        "custom_yara_url": state.cfg.yara_rules_url.is_some(),
        "client_ip": ip.to_string(),
    })
}

async fn get_settings(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    _admin: Administrator,
) -> Json<Value> {
    Json(settings_payload(&state, ip))
}

fn new_webhook_id() -> String {
    format!("wh_{}", hex::encode(crate::util::random_bytes::<4>()))
}

/// Secrets are never sent back to the browser: a missing value keeps the saved one. Generic
/// webhooks get a signing secret when created or rotated; the new ones are returned once.
fn restore_secrets(
    input: &mut Value,
    current: &Settings,
) -> Result<BTreeMap<String, String>, ApiError> {
    let key = match input.pointer("/malwarebazaar/auth_key") {
        None | Some(Value::Null) => current
            .malwarebazaar
            .auth_key
            .clone()
            .map_or(Value::Null, Value::String),
        Some(Value::String(s)) if s.trim().is_empty() => Value::Null,
        Some(Value::String(s)) => Value::String(s.trim().to_string()),
        Some(_) => return Err(invalid("the abuse.ch Auth-Key must be text")),
    };
    if let Some(bazaar) = input
        .get_mut("malwarebazaar")
        .and_then(Value::as_object_mut)
    {
        bazaar.insert("auth_key".into(), key);
    }
    let mut new_secrets = BTreeMap::new();
    if let Some(hooks) = input.get_mut("webhooks").and_then(Value::as_array_mut) {
        for hook in hooks {
            let hook = hook
                .as_object_mut()
                .ok_or_else(|| invalid("invalid webhook"))?;
            let saved = hook
                .get("id")
                .and_then(Value::as_str)
                .and_then(|id| current.webhooks.iter().find(|w| w.id == id));
            let url = hook
                .get("url")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .map(str::to_string);
            match (url, saved) {
                (Some(url), _) => {
                    hook.insert("url".into(), json!(url));
                }
                (None, Some(saved)) => {
                    hook.insert("url".into(), json!(saved.url));
                }
                (None, None) => return Err(invalid("enter the URL of each webhook")),
            }
            if saved.is_none() {
                hook.insert("id".into(), json!(new_webhook_id()));
            }
            let generic = hook.get("kind").and_then(Value::as_str) == Some("generic");
            let rotate = hook.get("rotate_secret").and_then(Value::as_bool) == Some(true);
            let secret = match saved.and_then(|s| s.secret.clone()) {
                _ if !generic => None,
                Some(secret) if !rotate => Some(secret),
                _ => {
                    let secret = crate::notify::new_signing_secret();
                    let id = hook["id"].as_str().unwrap_or_default().to_string();
                    new_secrets.insert(id, secret.clone());
                    Some(secret)
                }
            };
            hook.insert("secret".into(), json!(secret));
        }
    }
    Ok(new_secrets)
}

fn changed_sections(before: &Settings, after: &Settings) -> Vec<&'static str> {
    let mut changed = Vec::new();
    let mut check = |name, differs: bool| {
        if differs {
            changed.push(name);
        }
    };
    check("ClamAV", before.clamav != after.clamav);
    check("signature feeds", before.feeds != after.feeds);
    check("YARA", before.yara != after.yara);
    check("MalwareBazaar", before.malwarebazaar != after.malwarebazaar);
    check("limits", before.limits != after.limits);
    check("file policy", before.policy != after.policy);
    check("webhooks", before.webhooks != after.webhooks);
    check("dashboard access", before.dashboard != after.dashboard);
    changed
}

async fn put_settings(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Administrator(session): Administrator,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let mut input: Value = parse_json(&body)?;
    let current = state.settings.get();
    let new_secrets = restore_secrets(&mut input, &current)?;
    let new: Settings =
        serde_json::from_value(input).map_err(|e| invalid(format!("invalid settings: {e}")))?;
    if !networks_allow(&new.dashboard.allowed_networks, ip) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "lockout",
            format!("your address {ip} is not in the list: add it, or you would lose access"),
        ));
    }
    let saved = state.settings.save(new).map_err(invalid)?;
    let changes = changed_sections(&current, &saved);
    if !changes.is_empty() {
        state.audit.record(
            "settings.updated",
            &session.user.username,
            Some(ip),
            changes.join(", "),
        );
    }
    let mut payload = settings_payload(&state, ip);
    payload["new_secrets"] = json!(new_secrets);
    Ok(Json(payload))
}

#[derive(Deserialize)]
struct UpdateNow {
    engine: String,
}

async fn update_now(
    State(state): State<AppState>,
    _admin: Administrator,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let input: UpdateNow = parse_json(&body)?;
    match input.engine.as_str() {
        "clamav" => state.scanner.clamav.request_update(),
        "yara" if state.scanner.yara.enabled() => state.scanner.yara.request_update(),
        "yara" => return Err(invalid("YARA is turned off")),
        _ => return Err(invalid("the engine must be clamav or yara")),
    }
    Ok(StatusCode::ACCEPTED)
}

#[derive(Deserialize)]
struct WebhookTest {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

async fn test_webhook(
    State(state): State<AppState>,
    Administrator(session): Administrator,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let input: WebhookTest = parse_json(&body)?;
    let url = input
        .url
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());
    let saved = input.id.and_then(|id| {
        state
            .settings
            .get()
            .webhooks
            .iter()
            .find(|w| w.id == id)
            .cloned()
    });
    let hook = match (url, saved) {
        (Some(url), saved) => {
            let kind = input
                .kind
                .or(saved.as_ref().map(|s| s.kind.clone()))
                .unwrap_or_else(|| "generic".into());
            // Signed only toward the saved address: no valid signature for another host.
            let secret = saved
                .filter(|s| s.url == url && kind == "generic")
                .and_then(|s| s.secret);
            Webhook {
                id: "test".into(),
                kind,
                url,
                events: vec!["security".into()],
                secret,
            }
        }
        (None, Some(saved)) => saved,
        (None, None) => return Err(invalid("enter the webhook URL")),
    };
    crate::settings::validate_webhook(&hook).map_err(invalid)?;
    let alert = Alert {
        event: Event::Security,
        level: Level::Info,
        title: "FileFender test alert".into(),
        text: format!(
            "Sent from the dashboard by {}: alerts will arrive here.",
            session.user.username
        ),
        data: json!({ "test": true }),
    };
    match state.notifier.deliver(&hook, &alert).await {
        Ok(status) => Ok(Json(json!({ "delivered": true, "status": status }))),
        Err(err) => Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "webhook_failed",
            err.message,
        )),
    }
}

async fn list_hashes(State(state): State<AppState>, _operator: Operator) -> Json<Value> {
    let (allowed, blocked) = state.hashlists.counts();
    Json(json!({
        "entries": state.hashlists.list(),
        "allow": allowed,
        "block": blocked,
        "max": crate::hashlist::MAX_ENTRIES,
    }))
}

#[derive(Deserialize)]
struct NewHash {
    sha256: String,
    list: ListKind,
    #[serde(default)]
    note: String,
}

async fn add_hash(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Operator(session): Operator,
    body: Bytes,
) -> Result<(StatusCode, Json<HashEntry>), ApiError> {
    let input: NewHash = parse_json(&body)?;
    let entry = state
        .hashlists
        .add(
            &input.sha256,
            input.list,
            &input.note,
            &session.user.username,
        )
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, "invalid_hash", e))?;
    let list = match entry.list {
        ListKind::Allow => "allowlist",
        ListKind::Block => "blocklist",
    };
    let mut detail = format!("{list}: {}", entry.sha256);
    if !entry.note.is_empty() {
        detail.push_str(&format!(" ({})", entry.note));
    }
    state
        .audit
        .record("hashlist.added", &session.user.username, Some(ip), detail);
    Ok((StatusCode::CREATED, Json(entry)))
}

async fn remove_hash(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Operator(session): Operator,
    Path(sha256): Path<String>,
) -> Result<StatusCode, ApiError> {
    let removed = state
        .hashlists
        .remove(&sha256)
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, "invalid_hash", e))?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "unknown_hash",
                "this SHA-256 is in no list",
            )
        })?;
    state.audit.record(
        "hashlist.removed",
        &session.user.username,
        Some(ip),
        removed.sha256,
    );
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default)]
    limit: Option<usize>,
}

async fn audit_log(
    State(state): State<AppState>,
    _session: SignedIn,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = query.limit.unwrap_or(200).clamp(1, 1000);
    let audit = state.audit.clone();
    let entries = tokio::task::spawn_blocking(move || audit.recent(limit))
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "entries": entries })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_never_show_the_secret_part() {
        assert_eq!(
            url_hint("https://discord.com/api/webhooks/123/secret-token"),
            "discord.com/…"
        );
        assert_eq!(url_hint("https://user:pass@example.com/x"), "example.com/…");
        assert_eq!(url_hint("https://ntfy.sh/my-private-topic"), "ntfy.sh/…");
    }
}
