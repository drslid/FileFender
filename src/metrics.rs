use std::collections::VecDeque;
use std::fmt::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

use crate::scan::{ScanReport, Verdict};

const RECENT: usize = 25;
const BUCKETS_MS: [u64; 10] = [10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

#[derive(Debug, Clone, Serialize)]
pub struct RecentScan {
    pub at: String,
    pub name: Option<String>,
    pub size: u64,
    pub sha256: String,
    pub verdict: Verdict,
    pub threat: Option<String>,
    pub duration_ms: u64,
    pub cached: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsSnapshot {
    pub total: u64,
    pub clean: u64,
    pub suspicious: u64,
    pub malicious: u64,
    pub errors: u64,
    pub rejected: u64,
    pub cache_hits: u64,
    pub bytes: u64,
    pub average_ms: u64,
}

#[derive(Default)]
pub struct Stats {
    clean: AtomicU64,
    suspicious: AtomicU64,
    malicious: AtomicU64,
    errors: AtomicU64,
    rejected: AtomicU64,
    cache_hits: AtomicU64,
    bytes: AtomicU64,
    duration_ms_sum: AtomicU64,
    buckets: [AtomicU64; BUCKETS_MS.len()],
    recent: Mutex<VecDeque<RecentScan>>,
}

impl Stats {
    pub fn record(&self, report: &ScanReport) {
        match report.verdict {
            Verdict::Clean => &self.clean,
            Verdict::Suspicious => &self.suspicious,
            Verdict::Malicious => &self.malicious,
        }
        .fetch_add(1, Ordering::Relaxed);
        if report.cached {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        }
        self.bytes
            .fetch_add(report.file.size.unwrap_or(0), Ordering::Relaxed);
        self.duration_ms_sum
            .fetch_add(report.duration_ms, Ordering::Relaxed);
        for (bucket, limit) in self.buckets.iter().zip(BUCKETS_MS) {
            if report.duration_ms <= limit {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut recent = self.recent.lock().unwrap();
        if recent.len() == RECENT {
            recent.pop_back();
        }
        recent.push_front(RecentScan {
            at: report.scanned_at.clone(),
            name: report.file.name.clone(),
            size: report.file.size.unwrap_or(0),
            sha256: report.file.sha256.clone(),
            verdict: report.verdict,
            threat: report.threats.first().map(|t| t.name.clone()),
            duration_ms: report.duration_ms,
            cached: report.cached,
        });
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rejected(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        let clean = self.clean.load(Ordering::Relaxed);
        let suspicious = self.suspicious.load(Ordering::Relaxed);
        let malicious = self.malicious.load(Ordering::Relaxed);
        let total = clean + suspicious + malicious;
        StatsSnapshot {
            total,
            clean,
            suspicious,
            malicious,
            errors: self.errors.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            average_ms: self
                .duration_ms_sum
                .load(Ordering::Relaxed)
                .checked_div(total)
                .unwrap_or(0),
        }
    }

    pub fn recent(&self) -> Vec<RecentScan> {
        self.recent.lock().unwrap().iter().cloned().collect()
    }

    /// Prometheus text exposition.
    pub fn prometheus(&self, gauges: &[(&str, &str, f64)]) -> String {
        let s = self.snapshot();
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# HELP filefender_scans_total Completed scans by verdict."
        );
        let _ = writeln!(out, "# TYPE filefender_scans_total counter");
        for (verdict, value) in [
            ("clean", s.clean),
            ("suspicious", s.suspicious),
            ("malicious", s.malicious),
        ] {
            let _ = writeln!(
                out,
                "filefender_scans_total{{verdict=\"{verdict}\"}} {value}"
            );
        }
        for (name, help, value) in [
            (
                "filefender_scan_errors_total",
                "Scans that failed.",
                s.errors,
            ),
            (
                "filefender_scans_rejected_total",
                "Requests refused because the server was busy.",
                s.rejected,
            ),
            (
                "filefender_cache_hits_total",
                "Verdicts served from the cache.",
                s.cache_hits,
            ),
            (
                "filefender_scanned_bytes_total",
                "Bytes received for scanning.",
                s.bytes,
            ),
        ] {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}"
            );
        }
        let _ = writeln!(
            out,
            "# HELP filefender_scan_duration_milliseconds Scan duration."
        );
        let _ = writeln!(
            out,
            "# TYPE filefender_scan_duration_milliseconds histogram"
        );
        for (bucket, limit) in self.buckets.iter().zip(BUCKETS_MS) {
            let _ = writeln!(
                out,
                "filefender_scan_duration_milliseconds_bucket{{le=\"{limit}\"}} {}",
                bucket.load(Ordering::Relaxed)
            );
        }
        let _ = writeln!(
            out,
            "filefender_scan_duration_milliseconds_bucket{{le=\"+Inf\"}} {}",
            s.total
        );
        let _ = writeln!(
            out,
            "filefender_scan_duration_milliseconds_sum {}\nfilefender_scan_duration_milliseconds_count {}",
            self.duration_ms_sum.load(Ordering::Relaxed),
            s.total
        );
        for (name, help, value) in gauges {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}"
            );
        }
        out
    }
}
