use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub fn now_rfc3339() -> String {
    rfc3339(OffsetDateTime::now_utc())
}

pub fn rfc3339(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_default()
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("the operating system random generator is unavailable");
    bytes
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Atomically replaces `path` with `value` as JSON, readable by the owner only.
pub fn write_private_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = path.parent().context("the file has no parent directory")?;
    std::fs::create_dir_all(dir)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".filefender-")
        .tempfile_in(dir)?;
    tmp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer_pretty(&mut tmp, value)?;
    tmp.write_all(b"\n")?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Keeps file names safe to display and log: printable, single line, bounded length.
pub fn sanitize_filename(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && *c != '\u{202e}' && *c != '\u{202d}')
        .take(255)
        .collect();
    let cleaned = cleaned.trim().to_string();
    (!cleaned.is_empty()).then_some(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames_lose_paths_and_control_characters() {
        assert_eq!(
            sanitize_filename("../../etc/passwd").as_deref(),
            Some("passwd")
        );
        assert_eq!(
            sanitize_filename("C:\\Users\\a\\inv.pdf").as_deref(),
            Some("inv.pdf")
        );
        assert_eq!(
            sanitize_filename("a\nb\u{202e}fdp.exe").as_deref(),
            Some("abfdp.exe")
        );
        assert_eq!(sanitize_filename("  ").as_deref(), None);
    }

    #[test]
    fn rfc3339_has_second_precision() {
        let s = now_rfc3339();
        assert!(s.ends_with('Z') && !s.contains('.'), "{s}");
    }
}
