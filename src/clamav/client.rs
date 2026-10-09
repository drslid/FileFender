//! Minimal clamd client: null-terminated commands over the local Unix socket.

use std::fs::File;
use std::io::{IoSlice, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const MAX_REPLY: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Clean,
    Found(String),
    Error(String),
}

pub fn parse_reply(raw: &str) -> Reply {
    let raw = raw.trim_end_matches(['\0', '\n']).trim();
    // "fd[12]: Name FOUND", "stream: OK", or a bare "... ERROR" message.
    let result = match raw.split_once(": ") {
        Some((prefix, rest)) if prefix == "stream" || prefix.starts_with("fd[") => rest,
        _ => raw,
    };
    if result == "OK" {
        Reply::Clean
    } else if let Some(name) = result.strip_suffix(" FOUND") {
        Reply::Found(name.trim().to_string())
    } else if let Some(message) = result.strip_suffix(" ERROR") {
        Reply::Error(message.trim().to_string())
    } else {
        Reply::Error(format!("unexpected clamd reply: {result}"))
    }
}

pub async fn command(socket: &Path, command: &str, timeout: Duration) -> Result<String> {
    let exchange = async {
        let mut stream = UnixStream::connect(socket)
            .await
            .with_context(|| format!("cannot connect to clamd at {}", socket.display()))?;
        stream.write_all(format!("z{command}\0").as_bytes()).await?;
        let mut reply = Vec::with_capacity(128);
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            reply.extend_from_slice(&buf[..n]);
            if reply.contains(&0) || reply.len() > MAX_REPLY {
                break;
            }
        }
        let end = reply.iter().position(|b| *b == 0).unwrap_or(reply.len());
        Ok::<_, anyhow::Error>(String::from_utf8_lossy(&reply[..end]).trim().to_string())
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .with_context(|| format!("clamd did not answer {command} in time"))?
}

pub async fn ping(socket: &Path) -> Result<()> {
    let reply = command(socket, "PING", Duration::from_secs(5)).await?;
    if reply != "PONG" {
        bail!("unexpected PING reply: {reply}");
    }
    Ok(())
}

pub async fn version(socket: &Path) -> Result<String> {
    command(socket, "VERSION", Duration::from_secs(5)).await
}

pub async fn reload(socket: &Path) -> Result<()> {
    let reply = command(socket, "RELOAD", Duration::from_secs(10)).await?;
    if reply != "RELOADING" {
        bail!("unexpected RELOAD reply: {reply}");
    }
    Ok(())
}

/// Scans an open file by passing its descriptor to clamd (no copy of the data).
/// Blocking: call it from `spawn_blocking`.
pub fn scan_fd(socket: &Path, file: &File, timeout: Duration) -> Result<Reply> {
    let mut stream = StdUnixStream::connect(socket)
        .with_context(|| format!("cannot connect to clamd at {}", socket.display()))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.write_all(b"zFILDES\0")?;
    let fds = [file.as_raw_fd()];
    let control = [ControlMessage::ScmRights(&fds)];
    let payload = [IoSlice::new(&[0u8])];
    sendmsg::<()>(
        stream.as_raw_fd(),
        &payload,
        &control,
        MsgFlags::empty(),
        None,
    )
    .context("cannot pass the file descriptor to clamd")?;

    let mut reply = Vec::with_capacity(256);
    let mut buf = [0u8; 4096];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                bail!(
                    "clamd did not finish the scan within {}s",
                    timeout.as_secs()
                )
            }
            Err(err) => return Err(err.into()),
        };
        if n == 0 {
            break;
        }
        reply.extend_from_slice(&buf[..n]);
        if reply.contains(&0) || reply.len() > MAX_REPLY {
            break;
        }
    }
    if reply.is_empty() {
        bail!("clamd closed the connection without a result");
    }
    let end = reply.iter().position(|b| *b == 0).unwrap_or(reply.len());
    Ok(parse_reply(&String::from_utf8_lossy(&reply[..end])))
}

/// Parses `ClamAV 1.5.4/27788/Wed Oct  8 07:52:03 2026` into (`1.5.4`, `27788`).
pub fn parse_version(reply: &str) -> Option<(String, Option<u64>)> {
    let rest = reply.trim().strip_prefix("ClamAV ")?;
    let mut parts = rest.split('/');
    let engine = parts.next()?.trim().to_string();
    let daily = parts.next().and_then(|v| v.trim().parse().ok());
    Some((engine, daily))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scan_replies() {
        assert_eq!(parse_reply("fd[10]: OK"), Reply::Clean);
        assert_eq!(parse_reply("stream: OK\0"), Reply::Clean);
        assert_eq!(
            parse_reply("fd[10]: Win.Test.EICAR_HDB-1 FOUND"),
            Reply::Found("Win.Test.EICAR_HDB-1".into())
        );
        assert_eq!(
            parse_reply("fd[11]: Heuristics.Encrypted.Zip FOUND\n"),
            Reply::Found("Heuristics.Encrypted.Zip".into())
        );
        assert_eq!(
            parse_reply("INSTREAM size limit exceeded. ERROR"),
            Reply::Error("INSTREAM size limit exceeded.".into())
        );
        assert!(matches!(
            parse_reply("fd[9]: lstat() failed. ERROR"),
            Reply::Error(_)
        ));
        assert!(matches!(parse_reply("UNKNOWN COMMAND"), Reply::Error(_)));
        assert!(matches!(parse_reply(""), Reply::Error(_)));
    }

    #[test]
    fn parses_version() {
        assert_eq!(
            parse_version("ClamAV 1.5.4/27788/Wed Oct  8 07:52:03 2026"),
            Some(("1.5.4".into(), Some(27788)))
        );
        assert_eq!(parse_version("ClamAV 1.5.4"), Some(("1.5.4".into(), None)));
        assert_eq!(parse_version("PONG"), None);
    }
}
