// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

// "Is this build current?" — the same question the web dashboard's Devices
// card answers (see apps/web/dashboard.html), asked from inside the client
// so its local dashboard can say so too.
//
// The source of truth is apps/client/Cargo.toml as served by Caddy at
// <app>/client/Cargo.toml — exactly what the web dashboard compares against.
// Deliberately NOT GitHub releases: the source repo is private (so its
// releases aren't readable without a token), and a build made by install.sh
// has no .git directory to read a commit from anyway. The version number is
// the one thing every install type (source build or prebuilt image) already
// knows about itself.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

/// The newest client version the server advertises, once a check has
/// succeeded. None until then (or when checking is turned off), in which
/// case the dashboard just shows the running version with no verdict.
pub type LatestVersion = Arc<Mutex<Option<String>>>;

/// How often to re-check. Releases are rare; this only has to be often
/// enough that a long-running container notices one within the day.
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Where to look when UPDATE_CHECK_URL isn't set: the sibling `app.` host
/// of API_URL's `api.` host (api.filegarden.net -> app.filegarden.net), the
/// same pairing the production Caddyfile uses. None for any other shape of
/// API_URL (a self-hosted instance), where guessing would be wrong — those
/// can set UPDATE_CHECK_URL explicitly.
pub fn default_check_url(api_url: &str) -> Option<String> {
    let url = reqwest::Url::parse(api_url).ok()?;
    let host = url.host_str()?.strip_prefix("api.")?;
    Some(format!("{}://app.{}/client/Cargo.toml", url.scheme(), host))
}

/// Pulls `version = "x.y.z"` out of the [package] table of a Cargo.toml.
/// A hand-rolled scan instead of a TOML dependency: the file's shape is
/// ours, and this only needs one line of it.
pub fn parse_package_version(cargo_toml: &str) -> Option<String> {
    let mut in_package = false;
    for line in cargo_toml.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(rest) = line.strip_prefix("version") {
            let rest = rest.trim_start().strip_prefix('=')?.trim();
            let value = rest.strip_prefix('"')?.split('"').next()?;
            return Some(value.to_string());
        }
    }
    None
}

fn version_parts(v: &str) -> Vec<u64> {
    v.split(|c| c == '.' || c == '-')
        .take(3)
        .map(|n| n.parse().unwrap_or(0))
        .collect()
}

/// True if `running` is older than `latest` — numeric x.y.z comparison,
/// matching isOlderVersion() in apps/web/dashboard.html so the two
/// dashboards never disagree.
pub fn is_older(running: &str, latest: &str) -> bool {
    let (a, b) = (version_parts(running), version_parts(latest));
    for i in 0..3 {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x < y;
        }
    }
    false
}

/// Checks once, then every CHECK_INTERVAL, forever. A failed check (offline,
/// server down, unparseable file) just leaves the last known answer in
/// place — never an error the person has to act on, since "couldn't check"
/// and "up to date" are different things the dashboard must not conflate.
pub async fn run(http: reqwest::Client, url: String, latest: LatestVersion) {
    loop {
        match fetch_latest(&http, &url).await {
            Ok(version) => *latest.lock().unwrap() = Some(version),
            Err(err) => tracing::debug!(?err, %url, "update check failed; will retry"),
        }
        tokio::time::sleep(CHECK_INTERVAL).await;
    }
}

async fn fetch_latest(http: &reqwest::Client, url: &str) -> anyhow::Result<String> {
    let body = http
        .get(url)
        .timeout(Duration::from_secs(15))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    parse_package_version(&body).ok_or_else(|| anyhow::anyhow!("no [package] version in response"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_version_not_dependency_versions() {
        let toml = "[package]\nname = \"x\"\nversion = \"0.6.0\"\nedition = \"2024\"\n\n[dependencies]\naxum = { version = \"0.7\" }\n";
        assert_eq!(parse_package_version(toml).as_deref(), Some("0.6.0"));
        assert_eq!(parse_package_version("[dependencies]\nversion = \"9.9.9\"\n"), None);
    }

    #[test]
    fn compares_numerically() {
        assert!(is_older("0.5.0", "0.6.0"));
        assert!(is_older("0.9.0", "0.10.0"));
        assert!(!is_older("0.6.0", "0.6.0"));
        assert!(!is_older("1.0.0", "0.9.9"));
    }

    #[test]
    fn derives_app_host_from_api_host() {
        assert_eq!(
            default_check_url("https://api.filegarden.net").as_deref(),
            Some("https://app.filegarden.net/client/Cargo.toml")
        );
        assert_eq!(default_check_url("http://localhost:3000"), None);
    }
}
