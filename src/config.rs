use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};

pub const MIN_FRESHCLAM_INTERVAL: Duration = Duration::from_secs(3600);
pub const MAX_FILE_SIZE_LIMIT: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum AcmeDirectory {
    LetsEncrypt { staging: bool },
    Custom(String),
}

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub run_dir: PathBuf,
    pub tmp_dir: PathBuf,
    pub bind: IpAddr,
    pub http_port: u16,
    pub https_port: u16,
    pub domain: Option<String>,
    pub acme_email: Option<String>,
    pub acme_directory: AcmeDirectory,
    pub acme_ca_cert: Option<PathBuf>,
    pub duckdns_token: Option<String>,
    pub trust_proxy_headers: bool,
    pub max_file_size: u64,
    pub max_concurrent_scans: usize,
    pub max_pending_scans: usize,
    pub queue_timeout: Duration,
    pub upload_timeout: Duration,
    pub scan_timeout: Duration,
    pub cache_ttl: Duration,
    pub freshclam_interval: Duration,
    pub freshclam_mirror: Option<String>,
    pub clamd_bin: PathBuf,
    pub freshclam_bin: PathBuf,
    pub clamav_certs_dir: Option<PathBuf>,
    pub clamav_seed_dir: PathBuf,
    pub alert_encrypted: bool,
    pub alert_macros: bool,
    pub detect_pua: bool,
    pub low_memory: bool,
    pub yara_enabled: bool,
    pub yara_package: String,
    pub yara_malicious_score: i64,
    pub yara_rules_url: Option<String>,
    pub abusech_auth_key: Option<String>,
    pub log_json: bool,
    /// How long after start the first visitor may create the administrator; `None`: no limit.
    pub setup_window: Option<Duration>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let get = |name: &str| {
            lookup(&format!("FILEFENDER_{name}"))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let flag = |name: &str, default: bool| -> Result<bool> {
            match get(name) {
                None => Ok(default),
                Some(v) => parse_bool(&v).with_context(|| format!("FILEFENDER_{name}")),
            }
        };
        let duration = |name: &str, default: Duration| -> Result<Duration> {
            match get(name) {
                None => Ok(default),
                Some(v) => parse_duration(&v).with_context(|| format!("FILEFENDER_{name}")),
            }
        };
        let number = |name: &str, default: u64| -> Result<u64> {
            match get(name) {
                None => Ok(default),
                Some(v) => v
                    .parse::<u64>()
                    .with_context(|| format!("FILEFENDER_{name}: expected a whole number")),
            }
        };

        let domain = match get("DOMAIN") {
            Some(d) => Some(validate_domain(&d)?),
            None => None,
        };
        let tls = domain.is_some();

        let acme_directory = match get("ACME_DIRECTORY") {
            Some(url) if url.starts_with("https://") => AcmeDirectory::Custom(url),
            Some(_) => bail!("FILEFENDER_ACME_DIRECTORY must be an https:// URL"),
            None => AcmeDirectory::LetsEncrypt {
                staging: flag("ACME_STAGING", false)?,
            },
        };

        let acme_email = get("ACME_EMAIL");
        if let Some(email) = &acme_email
            && (!email.contains('@') || email.contains(char::is_whitespace))
        {
            bail!("FILEFENDER_ACME_EMAIL is not a valid e-mail address");
        }

        let duckdns_token = get("DUCKDNS_TOKEN");
        if duckdns_token.is_some() {
            match &domain {
                Some(d) if d.ends_with(".duckdns.org") && d.matches('.').count() == 2 => {}
                _ => {
                    bail!("FILEFENDER_DUCKDNS_TOKEN requires FILEFENDER_DOMAIN=<name>.duckdns.org")
                }
            }
        }

        let max_file_size = match get("MAX_FILE_SIZE") {
            Some(v) => parse_size(&v).context("FILEFENDER_MAX_FILE_SIZE")?,
            None => 100 * 1024 * 1024,
        };
        if !(1024..=MAX_FILE_SIZE_LIMIT).contains(&max_file_size) {
            bail!("FILEFENDER_MAX_FILE_SIZE must be between 1KiB and 2GiB");
        }

        let cpus = std::thread::available_parallelism().map_or(2, |n| n.get());
        let max_concurrent_scans = number("MAX_CONCURRENT_SCANS", cpus.clamp(2, 16) as u64)?;
        if !(1..=128).contains(&max_concurrent_scans) {
            bail!("FILEFENDER_MAX_CONCURRENT_SCANS must be between 1 and 128");
        }
        let max_pending_scans = number("MAX_PENDING_SCANS", max_concurrent_scans * 8)?;
        if max_pending_scans < max_concurrent_scans {
            bail!("FILEFENDER_MAX_PENDING_SCANS must be >= FILEFENDER_MAX_CONCURRENT_SCANS");
        }

        let mut freshclam_interval = duration("UPDATE_INTERVAL", MIN_FRESHCLAM_INTERVAL)?;
        if freshclam_interval < MIN_FRESHCLAM_INTERVAL {
            // The ClamAV CDN blocks clients that check more than once per hour.
            freshclam_interval = MIN_FRESHCLAM_INTERVAL;
        }

        let yara_package = get("YARA_PACKAGE").unwrap_or_else(|| "core".into());
        if !matches!(yara_package.as_str(), "core" | "extended" | "full") {
            bail!("FILEFENDER_YARA_PACKAGE must be core, extended or full");
        }
        let yara_malicious_score = number("YARA_MALICIOUS_SCORE", 70)?;
        if yara_malicious_score > 100 {
            bail!("FILEFENDER_YARA_MALICIOUS_SCORE must be between 0 and 100");
        }

        let bind = match get("BIND") {
            Some(v) => v
                .parse()
                .context("FILEFENDER_BIND: expected an IP address")?,
            None => IpAddr::from([0, 0, 0, 0]),
        };
        let port = |name: &str, default: u16| -> Result<u16> {
            match get(name) {
                None => Ok(default),
                Some(v) => v
                    .parse::<u16>()
                    .ok()
                    .filter(|p| *p > 0)
                    .with_context(|| format!("FILEFENDER_{name}: expected a TCP port")),
            }
        };

        let data_dir = PathBuf::from(get("DATA_DIR").unwrap_or_else(|| "/data".into()));
        let setup_window = Some(duration("SETUP_WINDOW", Duration::from_secs(1800))?)
            .filter(|window| !window.is_zero());
        let tmp_dir = get("TMP_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("filefender"));
        let config = Config {
            run_dir: get("RUN_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| tmp_dir.join("run")),
            tmp_dir,
            bind,
            http_port: port("HTTP_PORT", if tls { 80 } else { 8080 })?,
            https_port: port("HTTPS_PORT", 443)?,
            domain,
            acme_email,
            acme_directory,
            acme_ca_cert: get("ACME_CA_CERT").map(PathBuf::from),
            duckdns_token,
            trust_proxy_headers: flag("TRUST_PROXY_HEADERS", false)?,
            max_file_size,
            max_concurrent_scans: max_concurrent_scans as usize,
            max_pending_scans: max_pending_scans as usize,
            queue_timeout: duration("QUEUE_TIMEOUT", Duration::from_secs(30))?,
            upload_timeout: duration("UPLOAD_TIMEOUT", Duration::from_secs(600))?,
            scan_timeout: duration("SCAN_TIMEOUT", Duration::from_secs(120))?,
            cache_ttl: duration("CACHE_TTL", Duration::from_secs(6 * 3600))?,
            freshclam_interval,
            freshclam_mirror: get("CLAMAV_PRIVATE_MIRROR"),
            clamd_bin: PathBuf::from(get("CLAMD_BIN").unwrap_or_else(|| "clamd".into())),
            freshclam_bin: PathBuf::from(
                get("FRESHCLAM_BIN").unwrap_or_else(|| "freshclam".into()),
            ),
            clamav_certs_dir: get("CLAMAV_CERTS_DIR").map(PathBuf::from),
            clamav_seed_dir: PathBuf::from(
                get("CLAMAV_SEED_DIR").unwrap_or_else(|| "/var/lib/clamav".into()),
            ),
            alert_encrypted: flag("ALERT_ENCRYPTED", true)?,
            alert_macros: flag("ALERT_MACROS", false)?,
            detect_pua: flag("DETECT_PUA", false)?,
            low_memory: flag("LOW_MEMORY", false)?,
            yara_enabled: flag("YARA", true)?,
            yara_package,
            yara_malicious_score: yara_malicious_score as i64,
            yara_rules_url: get("YARA_RULES_URL"),
            abusech_auth_key: get("ABUSECH_AUTH_KEY"),
            log_json: get("LOG_FORMAT").is_some_and(|f| f.eq_ignore_ascii_case("json")),
            setup_window,
            data_dir,
        };
        Ok(config)
    }

    pub fn tls(&self) -> bool {
        self.domain.is_some()
    }

    pub fn clamav_db_dir(&self) -> PathBuf {
        self.data_dir.join("clamav")
    }

    pub fn keys_file(&self) -> PathBuf {
        self.data_dir.join("keys.json")
    }

    pub fn accounts_file(&self) -> PathBuf {
        self.data_dir.join("accounts.json")
    }

    pub fn settings_file(&self) -> PathBuf {
        self.data_dir.join("settings.json")
    }

    pub fn hashlist_file(&self) -> PathBuf {
        self.data_dir.join("hashlists.json")
    }

    pub fn audit_file(&self) -> PathBuf {
        self.data_dir.join("audit.log")
    }

    /// Port that serves `/healthz` and `/readyz` in plain HTTP inside the container.
    pub fn local_probe_port(&self) -> u16 {
        self.http_port
    }
}

fn validate_domain(value: &str) -> Result<String> {
    let domain = value.trim_end_matches('.').to_ascii_lowercase();
    if domain.contains("://") || domain.contains('/') || domain.contains(':') {
        bail!("FILEFENDER_DOMAIN must be a bare host name such as scan.example.com");
    }
    let labels: Vec<&str> = domain.split('.').collect();
    let valid = labels.len() >= 2
        && domain.len() <= 253
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if !valid {
        bail!("FILEFENDER_DOMAIN is not a valid host name: {value}");
    }
    Ok(domain)
}

pub fn parse_bool(value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => bail!("expected true or false, got {value:?}"),
    }
}

/// Parses `90`, `90s`, `15m`, `6h` or `1d`.
pub fn parse_duration(value: &str) -> Result<Duration> {
    let value = value.trim().to_ascii_lowercase();
    let (digits, unit) = value.split_at(
        value
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(value.len()),
    );
    let amount: u64 = digits
        .parse()
        .with_context(|| format!("invalid duration {value:?}"))?;
    let seconds = match unit.trim() {
        "" | "s" => amount,
        "m" => amount * 60,
        "h" => amount * 3600,
        "d" => amount * 86_400,
        other => bail!("invalid duration unit {other:?} (use s, m, h or d)"),
    };
    Ok(Duration::from_secs(seconds))
}

/// Parses `1048576`, `512K`, `100MB`, `100MiB`, `1G`... using powers of 1024.
pub fn parse_size(value: &str) -> Result<u64> {
    let value = value.trim().to_ascii_lowercase();
    let (digits, unit) = value.split_at(
        value
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(value.len()),
    );
    let amount: u64 = digits
        .parse()
        .with_context(|| format!("invalid size {value:?}"))?;
    let factor: u64 = match unit.trim() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        other => bail!("invalid size unit {other:?} (use K, M or G)"),
    };
    amount.checked_mul(factor).context("size is too large")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(vars: &[(&str, &str)]) -> Result<Config> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (format!("FILEFENDER_{k}"), v.to_string()))
            .collect();
        Config::from_lookup(|name| map.get(name).cloned())
    }

    #[test]
    fn defaults_serve_plain_http_on_8080() {
        let c = config(&[]).unwrap();
        assert!(!c.tls());
        assert_eq!(c.http_port, 8080);
        assert_eq!(c.max_file_size, 100 * 1024 * 1024);
        assert_eq!(c.freshclam_interval, MIN_FRESHCLAM_INTERVAL);
        assert!(c.yara_enabled && c.alert_encrypted && !c.alert_macros);
    }

    #[test]
    fn domain_enables_tls_on_standard_ports() {
        let c = config(&[("DOMAIN", "Scan.Example.com.")]).unwrap();
        assert_eq!(c.domain.as_deref(), Some("scan.example.com"));
        assert_eq!((c.http_port, c.https_port), (80, 443));
    }

    #[test]
    fn rejects_urls_and_bad_domains() {
        assert!(config(&[("DOMAIN", "https://scan.example.com")]).is_err());
        assert!(config(&[("DOMAIN", "localhost")]).is_err());
        assert!(config(&[("DOMAIN", "-bad.example.com")]).is_err());
    }

    #[test]
    fn duckdns_token_requires_a_duckdns_subdomain() {
        assert!(config(&[("DUCKDNS_TOKEN", "t")]).is_err());
        assert!(config(&[("DOMAIN", "scan.example.com"), ("DUCKDNS_TOKEN", "t")]).is_err());
        assert!(config(&[("DOMAIN", "a.b.duckdns.org"), ("DUCKDNS_TOKEN", "t")]).is_err());
        assert!(config(&[("DOMAIN", "myscan.duckdns.org"), ("DUCKDNS_TOKEN", "t")]).is_ok());
    }

    #[test]
    fn update_interval_cannot_go_below_one_hour() {
        let c = config(&[("UPDATE_INTERVAL", "5m")]).unwrap();
        assert_eq!(c.freshclam_interval, MIN_FRESHCLAM_INTERVAL);
        let c = config(&[("UPDATE_INTERVAL", "3h")]).unwrap();
        assert_eq!(c.freshclam_interval, Duration::from_secs(3 * 3600));
    }

    #[test]
    fn parses_sizes_and_durations() {
        assert_eq!(parse_size("100MB").unwrap(), 100 * 1024 * 1024);
        assert_eq!(parse_size("1GiB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("2048").unwrap(), 2048);
        assert!(parse_size("12TB").is_err());
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86_400));
        assert!(parse_duration("soon").is_err());
    }

    #[test]
    fn rejects_out_of_range_limits() {
        assert!(config(&[("MAX_FILE_SIZE", "3G")]).is_err());
        assert!(config(&[("MAX_CONCURRENT_SCANS", "0")]).is_err());
        assert!(config(&[("MAX_CONCURRENT_SCANS", "8"), ("MAX_PENDING_SCANS", "4")]).is_err());
        assert!(config(&[("YARA_PACKAGE", "all")]).is_err());
        assert!(config(&[("ACME_DIRECTORY", "http://insecure/dir")]).is_err());
    }
}
