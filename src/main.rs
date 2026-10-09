mod account;
mod api;
mod audit;
mod bazaar;
mod clamav;
mod config;
mod duckdns;
mod hashlist;
mod keys;
mod manage;
mod metrics;
mod notify;
mod policy;
mod scan;
mod server;
mod settings;
mod status;
#[cfg(test)]
mod tests;
mod users;
mod util;
mod web;
mod yara;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::config::Config;

#[derive(Parser)]
#[command(
    name = "filefender",
    version,
    about = "Self-hosted malware scanning API: ClamAV + YARA-X in one container"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the API, the web dashboard and the engines (default).
    Serve,
    /// Manage API keys.
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Manage the dashboard accounts.
    Admin {
        #[command(subcommand)]
        action: AdminAction,
    },
    /// Exit with 0 when the local server answers (used by the Docker health check).
    Healthcheck {
        /// Also require every engine to be ready to scan.
        #[arg(long)]
        ready: bool,
    },
}

#[derive(Subcommand)]
enum KeysAction {
    /// Create a key and print it once.
    Create { label: String },
    /// List keys (the secrets themselves are never stored).
    List,
    /// Revoke a key by id or label.
    Revoke { id: String },
}

#[derive(Subcommand)]
enum AdminAction {
    /// List the dashboard accounts and their role.
    Status,
    /// Delete every account (forgotten password, lost phone): the next visitor creates a new administrator.
    Reset,
    /// Remove the dashboard network restriction (you locked yourself out).
    UnlockDashboard,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(),
        Command::Keys { action } => keys_command(action),
        Command::Admin { action } => admin_command(action),
        Command::Healthcheck { ready } => healthcheck(ready),
    };
    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing(json: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,rustls_acme=info,hyper=warn"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}

fn serve() -> Result<ExitCode> {
    let cfg = Arc::new(Config::from_env()?);
    init_tracing(cfg.log_json);
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(cfg))?;
    Ok(ExitCode::SUCCESS)
}

async fn run(cfg: Arc<Config>) -> Result<()> {
    tracing::info!(
        version = api::VERSION,
        yara_x = yara_x::VERSION,
        "starting FileFender"
    );
    prepare_dirs(&cfg)?;
    let listeners = server::bind(&cfg).await?;

    let keys = Arc::new(keys::KeyStore::open(&cfg.keys_file())?);
    let users = Arc::new(users::UserStore::open(
        &cfg.accounts_file(),
        cfg.setup_window,
    )?);
    if users.all()?.is_empty() {
        tracing::warn!(
            "no administrator account yet: open the dashboard {}to create it",
            setup_window_text(&cfg)
        );
    }
    if cfg.settings_file().is_file() {
        tracing::info!(
            "settings saved from the dashboard override the FILEFENDER_* detection variables"
        );
    }
    let settings = Arc::new(settings::SettingsStore::open(
        &cfg.settings_file(),
        settings::Settings::from_config(&cfg),
    )?);
    let hashlists = Arc::new(hashlist::HashLists::open(&cfg.hashlist_file())?);
    let http = http_client()?;
    let notifier = notify::Notifier::start(
        settings.clone(),
        webhook_client()?,
        cfg.domain.clone().unwrap_or_else(|| "FileFender".into()),
    );
    let audit = Arc::new(audit::Audit::new(cfg.audit_file(), Some(notifier.clone())));

    let clamav = Arc::new(clamav::Clamav::new(cfg.clone(), settings.clone()));
    let yara = Arc::new(yara::Yara::new(cfg.clone(), settings.clone(), http.clone()));
    let scanner = Arc::new(scan::Scanner::new(
        cfg.clone(),
        settings.clone(),
        hashlists,
        clamav.clone(),
        yara.clone(),
        http.clone(),
    ));

    tokio::spawn(clamav.clone().run());
    tokio::spawn(yara.clone().run());
    tokio::spawn(keys.clone().watch());
    tokio::spawn(users.clone().watch());
    tokio::spawn(settings.watch());
    tokio::spawn(notifier.clone().watch_engines(scanner.clone()));
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let Ok(mut hangup) = signal(SignalKind::hangup()) else {
            return;
        };
        while hangup.recv().await.is_some() {
            tracing::info!("SIGHUP: checking for new signatures and rules now");
            clamav.request_update();
            yara.request_update();
        }
    });

    let state = api::AppState::new(cfg, keys.clone(), users, scanner, audit, notifier);
    server::serve(state, http, listeners, shutdown_signal()).await?;
    keys.flush_usage();
    tracing::info!("stopped");
    Ok(())
}

fn http_client_builder() -> Result<reqwest::ClientBuilder> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .user_agent(concat!(
            "FileFender/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/drslid/FileFender)"
        ))
        .connect_timeout(Duration::from_secs(15)))
}

/// Outbound HTTPS (rule updates, DuckDNS, MalwareBazaar) with bundled Web PKI roots.
fn http_client() -> Result<reqwest::Client> {
    Ok(http_client_builder()?.build()?)
}

/// Webhooks never follow redirects: a webhook cannot bounce requests to another host.
fn webhook_client() -> Result<reqwest::Client> {
    Ok(http_client_builder()?
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

/// Creates the private working directories and removes uploads left by a crash.
fn prepare_dirs(cfg: &Config) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(&cfg.data_dir)
        .with_context(|| format!("cannot create {}", cfg.data_dir.display()))?;
    let uploads = cfg.tmp_dir.join("uploads");
    if uploads.exists() {
        std::fs::remove_dir_all(&uploads).ok();
    }
    for dir in [&cfg.tmp_dir, &uploads] {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("cannot listen for SIGTERM");
    tokio::select! {
        _ = term.recv() => {},
        _ = tokio::signal::ctrl_c() => {},
    }
    tracing::info!("shutting down: finishing the scans in progress");
}

fn keys_command(action: KeysAction) -> Result<ExitCode> {
    let cfg = Config::from_env()?;
    let path = cfg.keys_file();
    let audit = audit::Audit::new(cfg.audit_file(), None);
    match action {
        KeysAction::Create { label } => {
            let (key, secret) = keys::create(&path, &label)?;
            audit.record(
                "key.created",
                "cli",
                None,
                format!("{} ({})", key.label, key.id),
            );
            println!(
                "Created API key {} ({}). Store it now, it is not shown again:\n\n{secret}\n",
                key.id, key.label
            );
        }
        KeysAction::List => {
            let list = keys::list(&path)?;
            if list.is_empty() {
                println!("No API key. Create one with: filefender keys create <label>");
            }
            for key in list {
                println!("{}  {}  {}", key.id, key.created_at, key.label);
            }
        }
        KeysAction::Revoke { id } => {
            let key = keys::revoke(&path, &id)?;
            audit.record(
                "key.revoked",
                "cli",
                None,
                format!("{} ({})", key.label, key.id),
            );
            println!(
                "Revoked {} ({}). Running servers stop accepting it within seconds.",
                key.id, key.label
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn setup_window_text(cfg: &Config) -> String {
    match cfg.setup_window {
        Some(window) => format!("within {} minutes ", window.as_secs().div_ceil(60)),
        None => String::new(),
    }
}

fn admin_command(action: AdminAction) -> Result<ExitCode> {
    let cfg = Config::from_env()?;
    let path = cfg.accounts_file();
    match action {
        AdminAction::Status => {
            let users = users::read(&path)?;
            if users.is_empty() {
                println!("No account yet: open the dashboard to create the administrator account.");
            } else {
                println!("Accounts: {}", users.len());
                for user in users {
                    println!(
                        "  {}  {}  two-factor {}",
                        user.username,
                        user.role.as_str(),
                        if user.totp.is_some() { "on" } else { "off" }
                    );
                }
            }
        }
        AdminAction::Reset => {
            if users::reset(&path)? {
                audit::Audit::new(cfg.audit_file(), None).record("admin.reset", "cli", None, "");
                println!(
                    "Every dashboard account was deleted. Open the dashboard {}to create a new administrator account.",
                    setup_window_text(&cfg)
                );
            } else {
                println!("There is no dashboard account.");
            }
        }
        AdminAction::UnlockDashboard => {
            settings::edit_file(
                &cfg.settings_file(),
                settings::Settings::from_config(&cfg),
                |s| s.dashboard.allowed_networks.clear(),
            )?;
            audit::Audit::new(cfg.audit_file(), None).record(
                "dashboard.unlocked",
                "cli",
                None,
                "network restriction removed",
            );
            println!(
                "The dashboard opens from any address again (a running server applies it within seconds)."
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn healthcheck(ready: bool) -> Result<ExitCode> {
    let cfg = Config::from_env()?;
    let path = if ready { "/readyz" } else { "/healthz" };
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, cfg.local_probe_port()));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = Vec::new();
    stream.take(4096).read_to_end(&mut response)?;
    let status_line = String::from_utf8_lossy(&response);
    let ok = status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200");
    Ok(if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
