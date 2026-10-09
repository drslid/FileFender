//! Optional hash reputation from MalwareBazaar (abuse.ch). Only the SHA-256 leaves
//! the server, never the file.

use std::time::Duration;

use anyhow::{Result, bail};
use serde::Deserialize;

const API: &str = "https://mb-api.abuse.ch/api/v1/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reputation {
    Known { family: Option<String> },
    Unknown,
}

pub struct Bazaar {
    http: reqwest::Client,
    endpoint: String,
    auth_key: String,
    cache: moka::sync::Cache<[u8; 32], Reputation>,
}

#[derive(Deserialize)]
struct Response {
    query_status: String,
    #[serde(default)]
    data: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    signature: Option<String>,
}

impl Bazaar {
    pub fn new(http: reqwest::Client, auth_key: String) -> Self {
        Self::with_endpoint(http, auth_key, API.to_string())
    }

    pub fn with_endpoint(http: reqwest::Client, auth_key: String, endpoint: String) -> Self {
        Bazaar {
            http,
            endpoint,
            auth_key,
            cache: moka::sync::Cache::builder()
                .max_capacity(100_000)
                .time_to_live(Duration::from_secs(3600))
                .build(),
        }
    }

    pub fn cached_entries(&self) -> u64 {
        self.cache.run_pending_tasks();
        self.cache.entry_count()
    }

    pub fn uses_key(&self, key: &str) -> bool {
        self.auth_key == key
    }

    pub async fn lookup(&self, sha256: &[u8; 32]) -> Result<Reputation> {
        if let Some(hit) = self.cache.get(sha256) {
            return Ok(hit);
        }
        let response: Response = self
            .http
            .post(&self.endpoint)
            .header("Auth-Key", &self.auth_key)
            .form(&[("query", "get_info"), ("hash", &hex::encode(sha256))])
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| e.without_url())?
            .error_for_status()
            .map_err(|e| e.without_url())?
            .json()
            .await
            .map_err(|e| e.without_url())?;
        let reputation = match response.query_status.as_str() {
            "ok" => Reputation::Known {
                family: response
                    .data
                    .into_iter()
                    .find_map(|e| e.signature)
                    .filter(|s| !s.trim().is_empty()),
            },
            "hash_not_found" => Reputation::Unknown,
            other => bail!("MalwareBazaar answered {other}"),
        };
        self.cache.insert(*sha256, reputation.clone());
        Ok(reputation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use axum::{Form, Json, Router};
    use std::collections::HashMap;

    async fn fake_api(Form(form): Form<HashMap<String, String>>) -> Json<serde_json::Value> {
        let known = "a".repeat(64);
        if form.get("hash") == Some(&known) {
            Json(serde_json::json!({"query_status": "ok", "data": [{"signature": "AgentTesla"}]}))
        } else {
            Json(serde_json::json!({"query_status": "hash_not_found"}))
        }
    }

    #[tokio::test]
    async fn classifies_known_and_unknown_hashes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(
            axum::serve(listener, Router::new().route("/api/v1/", post(fake_api))).into_future(),
        );

        let bazaar = Bazaar::with_endpoint(
            crate::http_client().unwrap(),
            "key".into(),
            format!("http://{addr}/api/v1/"),
        );
        let known = [0xaa; 32];
        assert_eq!(
            bazaar.lookup(&known).await.unwrap(),
            Reputation::Known {
                family: Some("AgentTesla".into())
            }
        );
        assert_eq!(
            bazaar.lookup(&[0x11; 32]).await.unwrap(),
            Reputation::Unknown
        );
        assert_eq!(bazaar.cached_entries(), 2);
    }
}
