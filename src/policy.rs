//! File type policy: refuses whole categories of files and executables in disguise, whatever
//! the signatures say. Categories come from the extension and from the content (magic bytes).

use crate::scan::{Threat, Verdict};
use crate::settings::Policy;

/// Content types that run as native or virtual machine code.
const EXECUTABLE_TYPES: &[&str] = &[
    "application/vnd.microsoft.portable-executable",
    "application/x-executable",
    "application/x-mach-binary",
    "application/vnd.android.dex",
    "application/java",
];

const ARCHIVE_TYPES: &[&str] = &[
    "application/zip",
    "application/x-tar",
    "application/vnd.rar",
    "application/gzip",
    "application/x-bzip2",
    "application/vnd.bzip3",
    "application/x-7z-compressed",
    "application/x-xz",
    "application/vnd.ms-cab-compressed",
    "application/x-unix-archive",
    "application/x-compress",
    "application/x-lzip",
    "application/zstd",
    "application/x-lz4",
    "application/x-cpio",
];

const CATEGORIES: &[(&str, &[&str])] = &[
    (
        "executables",
        &[
            "exe",
            "dll",
            "scr",
            "com",
            "cpl",
            "msi",
            "msp",
            "msix",
            "msixbundle",
            "appx",
            "appxbundle",
            "sys",
            "drv",
            "ocx",
            "xll",
            "lnk",
            "pif",
            "gadget",
            "application",
            "msc",
            "elf",
            "so",
            "dylib",
            "run",
            "appimage",
            "apk",
            "aab",
            "xapk",
            "ipa",
            "jar",
            "class",
            "dex",
            "deb",
            "rpm",
            "pkg",
            "mpkg",
        ],
    ),
    (
        "scripts",
        &[
            "js",
            "jse",
            "mjs",
            "cjs",
            "vbs",
            "vbe",
            "wsf",
            "wsh",
            "wsc",
            "sct",
            "hta",
            "ps1",
            "psm1",
            "psd1",
            "bat",
            "cmd",
            "sh",
            "bash",
            "zsh",
            "ksh",
            "csh",
            "py",
            "pyw",
            "pl",
            "rb",
            "php",
            "phtml",
            "phar",
            "applescript",
            "scpt",
            "command",
            "tool",
            "reg",
            "inf",
            "url",
            "scf",
            "chm",
            "iqy",
            "settingcontent-ms",
        ],
    ),
    (
        "macros",
        &[
            "docm", "dotm", "xlsm", "xltm", "xlam", "xla", "pptm", "potm", "ppam", "ppsm", "sldm",
        ],
    ),
    (
        "archives",
        &[
            "zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "zst", "cab", "lz",
            "lz4", "lzh", "lha", "arj", "ace", "cpio", "z", "ar", "zipx",
        ],
    ),
    (
        "disk_images",
        &[
            "iso", "img", "vhd", "vhdx", "vmdk", "vdi", "qcow2", "dmg", "udf", "toast",
        ],
    ),
    (
        "web_pages",
        &[
            "html", "htm", "xhtml", "xht", "shtml", "mht", "mhtml", "svg", "svgz",
        ],
    ),
];

/// Extensions of documents and media: an executable named like this is hiding.
const DOCUMENT_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "txt", "csv",
    "md", "json", "xml", "eml", "msg", "epub", "jpg", "jpeg", "png", "gif", "bmp", "webp", "tif",
    "tiff", "heic", "ico", "mp3", "mp4", "m4a", "mov", "avi", "mkv", "wav", "flac", "ogg", "webm",
    "wmv", "zip", "rar", "7z", "html",
];

/// What the policy needs to know about an upload.
pub struct Subject<'a> {
    pub name: Option<&'a str>,
    pub mime: Option<&'a str>,
    /// The original name contained right-to-left override characters (`exe.pdf` tricks).
    pub hidden_name: bool,
}

/// The content type from the first bytes. `infer` calls anything starting with `MZ` a
/// Windows program; a real one also has the `PE` header it points to.
pub fn content_type(head: &[u8]) -> Option<String> {
    let kind = infer::get(head)?.mime_type();
    if kind == EXECUTABLE_TYPES[0] {
        let offset = head
            .get(0x3c..0x40)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)?;
        if head.get(offset..offset.checked_add(4)?) != Some(b"PE\0\0".as_slice()) {
            return None;
        }
    }
    Some(kind.to_string())
}

/// `report.pdf.exe` gives `["pdf", "exe"]`; a leading dot (`.bashrc`) is not an extension.
fn extensions(name: &str) -> Vec<String> {
    name.trim_start_matches('.')
        .split('.')
        .skip(1)
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty() && e.len() <= 20)
        .collect()
}

fn extension_category(extension: &str) -> Option<&'static str> {
    CATEGORIES
        .iter()
        .find(|(_, extensions)| extensions.contains(&extension))
        .map(|(category, _)| *category)
}

fn content_category(mime: &str) -> Option<&'static str> {
    if EXECUTABLE_TYPES.contains(&mime) {
        Some("executables")
    } else if ARCHIVE_TYPES.contains(&mime) {
        Some("archives")
    } else if mime == "text/x-shellscript" {
        Some("scripts")
    } else if mime == "text/html" {
        Some("web_pages")
    } else if mime == "application/x-qemu-disk" {
        Some("disk_images")
    } else {
        None
    }
}

/// The categories of a file, from its last extension and its content.
pub fn categories(subject: &Subject) -> Vec<&'static str> {
    let mut found = Vec::new();
    if let Some(category) = subject
        .name
        .and_then(|n| extensions(n).pop())
        .and_then(|e| extension_category(&e))
    {
        found.push(category);
    }
    if let Some(category) = subject.mime.and_then(content_category)
        && !found.contains(&category)
    {
        found.push(category);
    }
    found
}

fn threat(name: String, description: String) -> Threat {
    Threat {
        engine: "policy",
        name,
        severity: Verdict::Malicious,
        description: Some(description),
        score: None,
        reference: None,
    }
}

pub fn active(policy: &Policy) -> bool {
    policy.disguised_files || !policy.blocked.is_empty()
}

pub fn check(policy: &Policy, subject: &Subject) -> Vec<Threat> {
    let mut threats = Vec::new();
    for category in categories(subject) {
        if policy.blocked.iter().any(|b| b == category) {
            let title: String = category
                .split('_')
                .map(|w| w[..1].to_ascii_uppercase() + &w[1..])
                .collect();
            threats.push(threat(
                format!("Policy.Blocked.{title}"),
                format!("This type of file is not accepted on this server ({category})"),
            ));
        }
    }
    if !policy.disguised_files {
        return threats;
    }
    if subject.hidden_name {
        threats.push(threat(
            "Policy.Disguised.Name".into(),
            "The file name hides its real extension with right-to-left characters".into(),
        ));
    }
    let extensions = subject.name.map(extensions).unwrap_or_default();
    let last = extensions.last().map(String::as_str);
    if subject.mime.is_some_and(|m| EXECUTABLE_TYPES.contains(&m))
        && last.is_some_and(|e| DOCUMENT_EXTENSIONS.contains(&e))
    {
        threats.push(threat(
            "Policy.Disguised.Executable".into(),
            "A program renamed to look like a document or a picture".into(),
        ));
    }
    if let [.., before, last] = extensions.as_slice()
        && DOCUMENT_EXTENSIONS.contains(&before.as_str())
        && matches!(extension_category(last), Some("executables" | "scripts"))
    {
        threats.push(threat(
            "Policy.Disguised.DoubleExtension".into(),
            format!("A .{last} file named like a .{before} document"),
        ));
    }
    threats
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(blocked: &[&str]) -> Policy {
        Policy {
            blocked: blocked.iter().map(|s| s.to_string()).collect(),
            disguised_files: true,
        }
    }

    fn names(threats: &[Threat]) -> Vec<&str> {
        threats.iter().map(|t| t.name.as_str()).collect()
    }

    const PE: Option<&str> = Some("application/vnd.microsoft.portable-executable");

    #[test]
    fn windows_programs_need_a_pe_header() {
        let mut program = vec![0u8; 0x80];
        program[..2].copy_from_slice(b"MZ");
        program[0x3c] = 0x40;
        program[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert_eq!(content_type(&program).as_deref(), PE);
        assert_eq!(content_type(b"MZ is how this text starts"), None);
        program[0x3c] = 0xff;
        assert_eq!(content_type(&program), None);
        let mut elf = b"\x7fELF\x02\x01\x01".to_vec();
        elf.resize(64, 0);
        assert_eq!(
            content_type(&elf).as_deref(),
            Some("application/x-executable")
        );
    }

    #[test]
    fn categories_from_name_and_content() {
        let subject = |name, mime| Subject {
            name,
            mime,
            hidden_name: false,
        };
        assert_eq!(
            categories(&subject(Some("setup.EXE"), None)),
            ["executables"]
        );
        assert_eq!(categories(&subject(Some("photo.jpg"), PE)), ["executables"]);
        assert_eq!(
            categories(&subject(Some("a.zip"), Some("application/zip"))),
            ["archives"]
        );
        assert_eq!(categories(&subject(Some("Invoice.xlsm"), None)), ["macros"]);
        assert_eq!(categories(&subject(Some("page.svg"), None)), ["web_pages"]);
        assert!(categories(&subject(Some(".bashrc"), None)).is_empty());
        assert!(categories(&subject(None, None)).is_empty());
    }

    #[test]
    fn blocked_categories_are_refused() {
        let found = check(
            &policy(&["executables", "disk_images"]),
            &Subject {
                name: Some("tool.iso"),
                mime: None,
                hidden_name: false,
            },
        );
        assert_eq!(names(&found), ["Policy.Blocked.DiskImages"]);
        assert_eq!(found[0].severity, Verdict::Malicious);
        let clean = check(
            &policy(&["executables"]),
            &Subject {
                name: Some("report.pdf"),
                mime: Some("application/pdf"),
                hidden_name: false,
            },
        );
        assert!(clean.is_empty());
    }

    #[test]
    fn disguised_files_are_caught() {
        let p = policy(&[]);
        let found = |name, mime, hidden_name| {
            names(&check(
                &p,
                &Subject {
                    name: Some(name),
                    mime,
                    hidden_name,
                },
            ))
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
        };
        assert_eq!(found("cat.jpg", PE, false), ["Policy.Disguised.Executable"]);
        assert_eq!(
            found("invoice.pdf.exe", PE, false),
            ["Policy.Disguised.DoubleExtension"]
        );
        assert_eq!(
            found("invoice.pdf   .js", None, false),
            ["Policy.Disguised.DoubleExtension"]
        );
        assert_eq!(found("invoicefdp.exe", PE, true), ["Policy.Disguised.Name"]);
        assert!(found("setup.v1.2.exe", PE, false).is_empty());
        assert!(found("backup.tar.gz", None, false).is_empty());
        assert!(found("libfoo.so", Some("application/x-executable"), false).is_empty());

        let off = Policy {
            blocked: Vec::new(),
            disguised_files: false,
        };
        assert!(!active(&off));
        assert!(
            check(
                &off,
                &Subject {
                    name: Some("cat.jpg"),
                    mime: PE,
                    hidden_name: true
                }
            )
            .is_empty()
        );
    }
}
