use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::StreamExt;
use rustls_acme::caches::DirCache;
use rustls_acme::{AcmeConfig, EventOk};
use tokio::net::TcpListener;

use crate::api::{self, AppState};
use crate::config::{AcmeDirectory, Config};
use crate::duckdns::DuckDns;
use crate::util::now_rfc3339;

pub struct Listeners {
    http: TcpListener,
    https: Option<std::net::TcpListener>,
}

/// Binds the ports first, so a busy port fails before any engine starts.
pub async fn bind(cfg: &Config) -> Result<Listeners> {
    let http_addr = SocketAddr::new(cfg.bind, cfg.http_port);
    let http = TcpListener::bind(http_addr)
        .await
        .with_context(|| format!("cannot listen on {http_addr}"))?;
    let https = match cfg.tls() {
        true => {
            let addr = SocketAddr::new(cfg.bind, cfg.https_port);
            let listener = std::net::TcpListener::bind(addr)
                .with_context(|| format!("cannot listen on {addr}"))?;
            listener.set_nonblocking(true)?;
            Some(listener)
        }
        false => None,
    };
    Ok(Listeners { http, https })
}

pub async fn serve(
    state: AppState,
    http: reqwest::Client,
    listeners: Listeners,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let cfg = state.cfg.clone();
    let app = api::router(state.clone());

    let (Some(domain), Some(https_listener)) = (cfg.domain.clone(), listeners.https) else {
        let addr = listeners.http.local_addr()?;
        tracing::info!(%addr, "serving HTTP (TLS off: put FileFender behind an HTTPS reverse proxy)");
        axum::serve(
            listeners.http,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown)
        .await?;
        return Ok(());
    };

    if let Some(token) = cfg.duckdns_token.clone() {
        let duckdns = DuckDns::new(http, &domain, token);
        duckdns.first_update().await;
        tokio::spawn(duckdns.keep_updated());
    }

    let acme = match &cfg.acme_ca_cert {
        Some(path) => AcmeConfig::new_with_client_config([&domain], client_config(path)?),
        None => AcmeConfig::new([&domain]),
    };
    let acme = match &cfg.acme_email {
        Some(email) => acme.contact_push(format!("mailto:{email}")),
        None => acme,
    };
    let acme = match &cfg.acme_directory {
        AcmeDirectory::LetsEncrypt { staging } => acme.directory_lets_encrypt(!staging),
        AcmeDirectory::Custom(url) => acme.directory(url),
    };
    let mut acme = acme.cache(DirCache::new(cfg.data_dir.join("acme"))).state();
    let acceptor = acme.axum_acceptor(acme.default_rustls_config());
    let tls = state.tls.clone();
    tokio::spawn(async move {
        while let Some(event) = acme.next().await {
            let mut tls = tls.write().unwrap();
            match event {
                Ok(EventOk::DeployedCachedCert | EventOk::DeployedNewCert) => {
                    tracing::info!("TLS certificate active");
                    tls.certificate = "active";
                    tls.detail = None;
                    tls.updated_at = Some(now_rfc3339());
                }
                Ok(event) => tracing::debug!(?event, "ACME"),
                Err(err) => {
                    tracing::error!("certificate request failed: {err}");
                    if tls.certificate != "active" {
                        tls.certificate = "error";
                    }
                    tls.detail = Some(err.to_string());
                    tls.updated_at = Some(now_rfc3339());
                }
            }
        }
    });

    let handle = axum_server::Handle::new();
    let https_addr = https_listener.local_addr()?;
    let https = axum_server::from_tcp(https_listener)?
        .acceptor(acceptor)
        .handle(handle.clone())
        .serve(app.into_make_service_with_connect_info::<SocketAddr>());

    let http_addr = listeners.http.local_addr()?;
    let (stop_http, stopped) = tokio::sync::oneshot::channel::<()>();
    let redirect = axum::serve(
        listeners.http,
        api::redirect_router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = stopped.await;
    });

    tokio::spawn(async move {
        shutdown.await;
        handle.graceful_shutdown(Some(Duration::from_secs(30)));
        let _ = stop_http.send(());
    });
    tracing::info!(%domain, %https_addr, %http_addr, "serving HTTPS with Let's Encrypt (TLS-ALPN-01)");
    let (https, redirect) = tokio::join!(https, redirect);
    https.with_context(|| format!("cannot serve HTTPS on {https_addr}"))?;
    redirect?;
    Ok(())
}

/// Trusts an extra CA for the ACME directory, for test servers such as Pebble.
fn client_config(ca: &std::path::Path) -> Result<Arc<rustls::ClientConfig>> {
    use rustls::RootCertStore;
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in CertificateDer::pem_file_iter(ca)
        .with_context(|| format!("cannot read {}", ca.display()))?
    {
        roots.add(cert?)?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}
