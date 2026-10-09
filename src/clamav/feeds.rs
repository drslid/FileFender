//! Free third-party ClamAV signature feeds, off by default, downloaded by freshclam.
//! Only detection databases are accepted: a feed can never whitelist a file.

use crate::scan::Verdict;

pub struct Feed {
    pub id: &'static str,
    pub provider: &'static str,
    pub homepage: &'static str,
    pub urls: &'static [&'static str],
}

pub const FEEDS: &[Feed] = &[
    Feed {
        id: "sanesecurity-macros",
        provider: "Sanesecurity",
        homepage: "https://sanesecurity.com/",
        urls: &[concat!(
            "https://mirror.rollernet.us/sanesecurity/",
            "badmacro.ndb"
        )],
    },
    Feed {
        id: "sanesecurity-foxhole",
        provider: "Sanesecurity",
        homepage: "https://sanesecurity.com/",
        urls: &[
            concat!(
                "https://mirror.rollernet.us/sanesecurity/",
                "foxhole_generic.cdb"
            ),
            concat!(
                "https://mirror.rollernet.us/sanesecurity/",
                "foxhole_filename.cdb"
            ),
            concat!(
                "https://mirror.rollernet.us/sanesecurity/",
                "foxhole_js.cdb"
            ),
            concat!(
                "https://mirror.rollernet.us/sanesecurity/",
                "foxhole_js.ndb"
            ),
        ],
    },
    Feed {
        id: "sanesecurity-phishing",
        provider: "Sanesecurity",
        homepage: "https://sanesecurity.com/",
        urls: &[
            concat!("https://mirror.rollernet.us/sanesecurity/", "phish.ndb"),
            concat!("https://mirror.rollernet.us/sanesecurity/", "scam.ndb"),
            concat!("https://mirror.rollernet.us/sanesecurity/", "shelter.ldb"),
        ],
    },
    Feed {
        id: "urlhaus",
        provider: "abuse.ch URLhaus",
        homepage: "https://urlhaus.abuse.ch/",
        urls: &["https://urlhaus.abuse.ch/downloads/urlhaus.ndb"],
    },
    Feed {
        id: "interserver",
        provider: "InterServer",
        homepage: "https://sigs.interserver.net/",
        urls: &[
            "https://sigs.interserver.net/interserver256.hdb",
            "https://sigs.interserver.net/shell.ldb",
        ],
    },
    Feed {
        id: "rfxn",
        provider: "R-fx Networks Linux Malware Detect",
        homepage: "https://www.rfxn.com/projects/linux-malware-detect/",
        urls: &[
            "https://www.rfxn.com/downloads/rfxn.ndb",
            "https://www.rfxn.com/downloads/rfxn.hdb",
        ],
    },
];

pub fn find(id: &str) -> Option<&'static Feed> {
    FEEDS.iter().find(|feed| feed.id == id)
}

impl Feed {
    /// Database file names, as freshclam stores them.
    pub fn files(&self) -> impl Iterator<Item = &'static str> {
        self.urls
            .iter()
            .map(|url| url.rsplit('/').next().unwrap_or(url))
    }
}

/// Every file name a feed may create, enabled or not.
pub fn all_files() -> impl Iterator<Item = &'static str> {
    FEEDS.iter().flat_map(Feed::files)
}

/// Third-party signatures that flag risky content (types, links, phishing) rather than proven
/// malware are reported as suspicious; clamd suffixes them with `.UNOFFICIAL`.
pub fn severity(name: &str) -> Option<Verdict> {
    let name = name.strip_suffix(".UNOFFICIAL").unwrap_or(name);
    const SUSPICIOUS: [&str; 5] = [
        "Sanesecurity.Foxhole.",
        "Sanesecurity.Shelter.",
        "Sanesecurity.Phish",
        "Sanesecurity.Scam",
        "URLhaus.",
    ];
    SUSPICIOUS
        .iter()
        .any(|prefix| name.starts_with(prefix))
        .then_some(Verdict::Suspicious)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feeds_only_download_detection_databases() {
        for file in all_files() {
            let ext = file.rsplit('.').next().unwrap();
            assert!(
                ["ndb", "hdb", "hsb", "ldb", "cdb"].contains(&ext),
                "{file} could change what is allowed"
            );
        }
        for feed in FEEDS {
            assert!(feed.urls.iter().all(|u| u.starts_with("https://")));
        }
    }

    #[test]
    fn risk_feeds_are_suspicious() {
        assert_eq!(
            severity("Sanesecurity.Foxhole.Zip_exe.UNOFFICIAL"),
            Some(Verdict::Suspicious)
        );
        assert_eq!(
            severity("URLhaus.15711.UNOFFICIAL"),
            Some(Verdict::Suspicious)
        );
        assert_eq!(severity("Sanesecurity.Badmacro.Doc.ramf.UNOFFICIAL"), None);
        assert_eq!(severity("Win.Trojan.Agent-1"), None);
    }
}
