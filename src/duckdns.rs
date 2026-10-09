//! Keeps a DuckDNS name pointed at this server, for users without a domain.

use std::time::Duration;

use anyhow::{Result, bail};

const EVERY: Duration = Duration::from_secs(300);

pub struct DuckDns {
    http: reqwest::Client,
    subdomain: String,
    token: String,
}

impl DuckDns {
    pub fn new(http: reqwest::Client, domain: &str, token: String) -> Self {
        let subdomain = domain.trim_end_matches(".duckdns.org").to_string();
        DuckDns {
            http,
            subdomain,
            token,
        }
    }

    pub async fn update(&self) -> Result<()> {
        // An empty ip lets DuckDNS use the address the request comes from.
        let body = self
            .http
            .get("https://www.duckdns.org/update")
            .query(&[
                ("domains", self.subdomain.as_str()),
                ("token", self.token.as_str()),
                ("ip", ""),
            ])
            .timeout(Duration::from_secs(20))
            .send()
            .await
            .map_err(|e| e.without_url())?
            .text()
            .await
            .map_err(|e| e.without_url())?;
        if body.trim() != "OK" {
            bail!("DuckDNS refused the update; check the subdomain and the token");
        }
        Ok(())
    }

    /// Updates until DuckDNS accepts once (the certificate request needs the record).
    pub async fn first_update(&self) {
        let mut retry = Duration::from_secs(5);
        for _ in 0..8 {
            match self.update().await {
                Ok(()) => {
                    tracing::info!(domain = %format!("{}.duckdns.org", self.subdomain), "DuckDNS record updated");
                    return;
                }
                Err(err) => tracing::warn!("DuckDNS update failed: {err:#}"),
            }
            tokio::time::sleep(retry).await;
            retry = (retry * 2).min(Duration::from_secs(60));
        }
    }

    pub async fn keep_updated(self) {
        loop {
            tokio::time::sleep(EVERY).await;
            if let Err(err) = self.update().await {
                tracing::warn!("DuckDNS update failed: {err:#}");
            }
        }
    }
}
