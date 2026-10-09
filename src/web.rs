use std::sync::LazyLock;

use axum::extract::Path;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

use crate::api::VERSION;

const INDEX: &str = include_str!("../web/index.html");

struct Asset {
    name: &'static str,
    mime: &'static str,
    body: &'static [u8],
}

const ASSETS: &[Asset] = &[
    Asset {
        name: "app.js",
        mime: "text/javascript; charset=utf-8",
        body: include_bytes!("../web/app.js"),
    },
    Asset {
        name: "i18n.js",
        mime: "text/javascript; charset=utf-8",
        body: include_bytes!("../web/i18n.js"),
    },
    Asset {
        name: "app.css",
        mime: "text/css; charset=utf-8",
        body: include_bytes!("../web/app.css"),
    },
    Asset {
        name: "logo.svg",
        mime: "image/svg+xml",
        body: include_bytes!("../web/logo.svg"),
    },
];

/// Changes with the content of the embedded files, even between builds of one version.
pub static ASSET_TAG: LazyLock<String> = LazyLock::new(|| {
    let mut digest = Sha256::new();
    for asset in ASSETS {
        digest.update(asset.body);
    }
    hex::encode(&digest.finalize()[..6])
});

pub async fn index() -> Response {
    let html = INDEX
        .replace("{{VERSION}}", VERSION)
        .replace("{{ASSETS}}", &ASSET_TAG);
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
        ],
        html,
    )
        .into_response()
}

pub async fn asset(Path(name): Path<String>) -> Response {
    match ASSETS.iter().find(|a| a.name == name) {
        Some(asset) => (
            [
                (header::CONTENT_TYPE, HeaderValue::from_static(asset.mime)),
                // URLs carry ?v=<content hash>, so a new build never serves stale files.
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=604800, immutable"),
                ),
            ],
            asset.body,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
