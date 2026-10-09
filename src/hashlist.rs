//! SHA-256 allow and block lists, managed from the dashboard and kept in `hashlists.json`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const MAX_ENTRIES: usize = 50_000;
const MAX_NOTE: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListKind {
    /// Always clean: known good files that the engines flag by mistake.
    Allow,
    /// Always malicious: files seen in an incident, even before signatures know them.
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashEntry {
    pub sha256: String,
    pub list: ListKind,
    #[serde(default)]
    pub note: String,
    pub added_at: String,
    pub added_by: String,
}

#[derive(Default, Serialize, Deserialize)]
struct ListFile {
    entries: Vec<HashEntry>,
}

pub struct HashLists {
    path: Option<PathBuf>,
    entries: RwLock<HashMap<[u8; 32], Arc<HashEntry>>>,
    write: Mutex<()>,
}

pub fn parse_sha256(text: &str) -> Option<[u8; 32]> {
    let mut digest = [0u8; 32];
    let text = text.trim();
    (text.len() == 64 && hex::decode_to_slice(text, &mut digest).is_ok()).then_some(digest)
}

impl HashLists {
    pub fn open(path: &Path) -> Result<Self> {
        let file: ListFile = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("{} is not a valid list file", path.display()))?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => ListFile::default(),
            Err(err) => return Err(err).with_context(|| format!("cannot read {}", path.display())),
        };
        let lists = HashLists {
            path: Some(path.to_path_buf()),
            entries: RwLock::new(HashMap::new()),
            write: Mutex::new(()),
        };
        {
            let mut map = lists.entries.write().unwrap();
            for entry in file.entries {
                if let Some(digest) = parse_sha256(&entry.sha256) {
                    map.insert(digest, Arc::new(entry));
                }
            }
        }
        Ok(lists)
    }

    pub fn get(&self, sha256: &[u8; 32]) -> Option<Arc<HashEntry>> {
        self.entries.read().unwrap().get(sha256).cloned()
    }

    /// Newest first.
    pub fn list(&self) -> Vec<HashEntry> {
        let mut entries: Vec<HashEntry> = self
            .entries
            .read()
            .unwrap()
            .values()
            .map(|e| (**e).clone())
            .collect();
        entries.sort_by(|a, b| b.added_at.cmp(&a.added_at).then(a.sha256.cmp(&b.sha256)));
        entries
    }

    pub fn counts(&self) -> (usize, usize) {
        let entries = self.entries.read().unwrap();
        let blocked = entries
            .values()
            .filter(|e| e.list == ListKind::Block)
            .count();
        (entries.len() - blocked, blocked)
    }

    fn save(&self, map: &HashMap<[u8; 32], Arc<HashEntry>>) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut entries: Vec<HashEntry> = map.values().map(|e| (**e).clone()).collect();
        entries.sort_by(|a, b| a.added_at.cmp(&b.added_at).then(a.sha256.cmp(&b.sha256)));
        crate::util::write_private_json(path, &ListFile { entries }).map_err(|err| {
            tracing::error!("cannot save the hash lists: {err:#}");
            "cannot save the hash lists".to_string()
        })
    }

    /// Adds a hash, or moves it to the other list.
    pub fn add(
        &self,
        sha256: &str,
        list: ListKind,
        note: &str,
        by: &str,
    ) -> Result<HashEntry, String> {
        let digest = parse_sha256(sha256).ok_or("expected a SHA-256 in hexadecimal")?;
        let note = note.trim();
        if note.chars().count() > MAX_NOTE || note.chars().any(char::is_control) {
            return Err(format!(
                "the note must be {MAX_NOTE} printable characters at most"
            ));
        }
        let entry = HashEntry {
            sha256: hex::encode(digest),
            list,
            note: note.to_string(),
            added_at: crate::util::now_rfc3339(),
            added_by: by.to_string(),
        };
        let _guard = self.write.lock().unwrap();
        let mut map = self.entries.read().unwrap().clone();
        if !map.contains_key(&digest) && map.len() >= MAX_ENTRIES {
            return Err(format!("the lists are full ({MAX_ENTRIES} hashes)"));
        }
        map.insert(digest, Arc::new(entry.clone()));
        self.save(&map)?;
        *self.entries.write().unwrap() = map;
        Ok(entry)
    }

    pub fn remove(&self, sha256: &str) -> Result<Option<HashEntry>, String> {
        let digest = parse_sha256(sha256).ok_or("expected a SHA-256 in hexadecimal")?;
        let _guard = self.write.lock().unwrap();
        let mut map = self.entries.read().unwrap().clone();
        let Some(removed) = map.remove(&digest) else {
            return Ok(None);
        };
        self.save(&map)?;
        *self.entries.write().unwrap() = map;
        Ok(Some((*removed).clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_survive_a_restart_in_a_private_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hashlists.json");
        let lists = HashLists::open(&path).unwrap();
        let hash = "AB".repeat(32);
        lists
            .add(&hash, ListKind::Block, "incident 42", "admin")
            .unwrap();
        lists
            .add(&"cd".repeat(32), ListKind::Allow, "", "admin")
            .unwrap();
        assert!(lists.add("abc", ListKind::Block, "", "admin").is_err());
        assert!(
            lists
                .add(&hash, ListKind::Block, "line\nbreak", "admin")
                .is_err()
        );
        assert_eq!(lists.counts(), (1, 1));

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let reopened = HashLists::open(&path).unwrap();
        let entry = reopened.get(&[0xab; 32]).unwrap();
        assert_eq!(entry.list, ListKind::Block);
        assert_eq!(entry.sha256, "ab".repeat(32));

        // Adding again moves the hash to the other list.
        reopened
            .add(&hash, ListKind::Allow, "false positive", "admin")
            .unwrap();
        assert_eq!(reopened.counts(), (2, 0));
        assert!(reopened.remove(&hash).unwrap().is_some());
        assert!(reopened.remove(&hash).unwrap().is_none());
        assert_eq!(HashLists::open(&path).unwrap().list().len(), 1);
    }
}
