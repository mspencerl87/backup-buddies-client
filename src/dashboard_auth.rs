// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! Login for the local dashboard.
//!
//! The dashboard can restore decrypted files and edit the exclude list
//! (which removes files from buddies), so it isn't left open:
//!
//! - With DASHBOARD_PASSWORD set (and DASHBOARD_USER, default `admin`),
//!   every page and endpoint needs a login. Sessions are a random token in
//!   a cookie, kept in memory: a restart logs everyone out.
//! - Without it, the dashboard only answers requests from this machine
//!   itself, and everyone else gets a page saying how to set a password.
//!   There's no default password: one that works until someone changes it
//!   works for whoever on the network tries it first.
//!
//! Credentials come from .env rather than a first-login setup page for the
//! same reason: the dashboard is locked from the moment it starts.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const SESSION_LIFETIME: Duration = Duration::from_secs(30 * 24 * 3600);
// After this many wrong passwords in a row from one address, it has to
// wait LOCKOUT before trying again.
const MAX_FAILURES: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(60);

/// DASHBOARD_USER / DASHBOARD_PASSWORD from .env. Only hashes are kept, so
/// they can be compared in constant time without the lengths leaking.
pub struct Login {
    user_hash: [u8; 32],
    password_hash: [u8; 32],
}

fn sha256(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(Sha256::digest(text.as_bytes()).as_slice());
    out
}

fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Login {
    /// None when DASHBOARD_PASSWORD is unset or empty.
    pub fn from_env() -> Option<Self> {
        let password = std::env::var("DASHBOARD_PASSWORD").ok().filter(|p| !p.is_empty())?;
        if password.len() < 8 {
            tracing::warn!("DASHBOARD_PASSWORD is under 8 characters — anyone on your network can try guesses at it");
        }
        let user = std::env::var("DASHBOARD_USER")
            .ok()
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| "admin".to_string());
        Some(Login { user_hash: sha256(&user), password_hash: sha256(&password) })
    }

    fn matches(&self, user: &str, password: &str) -> bool {
        // Both compared every time, so a right user name isn't faster.
        let user_ok = same(&self.user_hash, &sha256(user.trim()));
        let password_ok = same(&self.password_hash, &sha256(password));
        user_ok & password_ok
    }
}

#[derive(Clone)]
pub struct Auth {
    inner: Arc<Inner>,
}

struct Inner {
    login: Option<Login>,
    // Per port, so two clients' dashboards on one host (each on its own
    // DASHBOARD_PORT) don't overwrite each other's session: cookies are
    // shared across ports.
    cookie_name: String,
    sessions: Mutex<HashMap<String, Instant>>,
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl Auth {
    pub fn new(login: Option<Login>, bind_addr: &str) -> Self {
        let port = bind_addr.rsplit(':').next().filter(|p| p.parse::<u16>().is_ok());
        let cookie_name = match port {
            Some(port) => format!("bb_session_{port}"),
            None => "bb_session".to_string(),
        };
        Auth {
            inner: Arc::new(Inner {
                login,
                cookie_name,
                sessions: Mutex::new(HashMap::new()),
                failures: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn login_enabled(&self) -> bool {
        self.inner.login.is_some()
    }

    fn session_from(&self, headers: &HeaderMap) -> Option<String> {
        let wanted = format!("{}=", self.inner.cookie_name);
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .find_map(|c| c.trim().strip_prefix(&wanted).map(str::to_string))
    }

    fn has_session(&self, headers: &HeaderMap) -> bool {
        let Some(token) = self.session_from(headers) else { return false };
        let mut sessions = self.inner.sessions.lock().unwrap();
        match sessions.get(&token) {
            Some(expires) if *expires > Instant::now() => true,
            Some(_) => {
                sessions.remove(&token);
                false
            }
            None => false,
        }
    }

    fn new_session(&self) -> String {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("the OS random number generator is unavailable");
        let token = hex::encode(bytes);
        let now = Instant::now();
        let mut sessions = self.inner.sessions.lock().unwrap();
        sessions.retain(|_, expires| *expires > now);
        sessions.insert(token.clone(), now + SESSION_LIFETIME);
        token
    }

    fn session_cookie(&self, token: &str, max_age: u64) -> String {
        // No `Secure`: the dashboard is plain HTTP on the local network.
        format!(
            "{}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}",
            self.inner.cookie_name
        )
    }

    /// Some(seconds to wait) while `ip` is locked out.
    fn locked_out(&self, ip: IpAddr) -> Option<u64> {
        let failures = self.inner.failures.lock().unwrap();
        let (count, last) = failures.get(&ip)?;
        let elapsed = last.elapsed();
        (*count >= MAX_FAILURES && elapsed < LOCKOUT).then(|| (LOCKOUT - elapsed).as_secs().max(1))
    }

    fn note_failure(&self, ip: IpAddr) {
        let mut failures = self.inner.failures.lock().unwrap();
        failures.retain(|_, (_, last)| last.elapsed() < Duration::from_secs(3600));
        let entry = failures.entry(ip).or_insert((0, Instant::now()));
        if entry.0 >= MAX_FAILURES {
            // A wrong guess after a lockout starts a new one.
            entry.0 = MAX_FAILURES - 1;
        }
        entry.0 += 1;
        entry.1 = Instant::now();
    }
}

/// Pages that work without a login: the login form itself and the icons
/// it shows.
fn is_public(path: &str) -> bool {
    matches!(path, "/login" | "/favicon.svg" | "/mark.svg")
}

/// The host name from a Host header, without the port.
fn host_name(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    host.split(':').next().unwrap_or(host)
}

/// A browser sends Origin with every POST. When it names another site, the
/// request was made by a page on that site (with the person's cookie
/// attached) — refuse it. SameSite alone doesn't cover this: every port on
/// the same host counts as the same site, so other web apps on a NAS would
/// get through.
fn cross_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    let origin_host = origin.split_once("://").map(|(_, h)| h).unwrap_or(origin);
    !origin_host.eq_ignore_ascii_case(host)
}

/// Runs in front of every route.
pub async fn require_login(
    State(auth): State<Auth>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let headers = req.headers();
    if req.method() != Method::GET && req.method() != Method::HEAD && cross_origin(headers) {
        return (StatusCode::FORBIDDEN, "Cross-site request refused").into_response();
    }

    if auth.inner.login.is_none() {
        // Local-only mode. Checking the Host header too stops DNS
        // rebinding: a web page on evil.example whose name points at
        // 127.0.0.1 would otherwise reach this from the person's browser.
        let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
        let local_host = matches!(host_name(host), "localhost" | "127.0.0.1" | "::1");
        if !peer.ip().to_canonical().is_loopback() || !local_host {
            return (StatusCode::FORBIDDEN, Html(local_only_page())).into_response();
        }
        if req.uri().path() == "/login" {
            return Redirect::to("/").into_response();
        }
        return next.run(req).await;
    }

    if is_public(req.uri().path()) || auth.has_session(headers) {
        return next.run(req).await;
    }
    if req.uri().path().starts_with("/api/") {
        return (StatusCode::UNAUTHORIZED, "Log in first").into_response();
    }
    Redirect::to("/login").into_response()
}

pub async fn login_page(State(auth): State<Auth>, headers: HeaderMap) -> Response {
    if auth.has_session(&headers) {
        return Redirect::to("/").into_response();
    }
    Html(login_html(None)).into_response()
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

pub async fn login_submit(
    State(auth): State<Auth>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Form(form): Form<LoginForm>,
) -> Response {
    let Some(login) = &auth.inner.login else {
        return Redirect::to("/").into_response();
    };
    let ip = peer.ip().to_canonical();
    if let Some(wait) = auth.locked_out(ip) {
        let msg = format!("Too many wrong passwords. Try again in {wait} seconds.");
        return (StatusCode::TOO_MANY_REQUESTS, Html(login_html(Some(&msg)))).into_response();
    }
    if !login.matches(&form.username, &form.password) {
        auth.note_failure(ip);
        tracing::warn!(from = %ip, "dashboard login failed");
        // Slows down guessing even before the lockout.
        tokio::time::sleep(Duration::from_millis(500)).await;
        return (StatusCode::UNAUTHORIZED, Html(login_html(Some("Wrong user name or password.")))).into_response();
    }
    auth.inner.failures.lock().unwrap().remove(&ip);
    let token = auth.new_session();
    let cookie = auth.session_cookie(&token, SESSION_LIFETIME.as_secs());
    ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
}

pub async fn logout(State(auth): State<Auth>, headers: HeaderMap) -> Response {
    if let Some(token) = auth.session_from(&headers) {
        auth.inner.sessions.lock().unwrap().remove(&token);
    }
    ([(header::SET_COOKIE, auth.session_cookie("", 0))], Redirect::to("/login")).into_response()
}

const PAGE_HEAD: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Backup Buddies — log in</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
  :root { --bg: #0f1115; --surface: #171a21; --border: #2a2e38; --text: #e8e9ec; --text-muted: #9499a6;
    --danger: #ff6b6b; --accent-grad: linear-gradient(135deg, #2ec5ff, #42e6a4); }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1rem;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.5; }
  .box { width: 100%; max-width: 380px; background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; padding: 1.5rem; }
  .title { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 1rem; }
  .title img { width: 26px; height: 26px; }
  h1 { font-size: 1.1rem; margin: 0; background: var(--accent-grad); -webkit-background-clip: text;
    background-clip: text; color: transparent; }
  label { display: block; font-size: 0.8rem; color: var(--text-muted); margin-top: 0.75rem; }
  input { width: 100%; margin-top: 0.25rem; padding: 0.5rem 0.65rem; border-radius: 8px; font-size: 0.95rem;
    border: 1px solid var(--border); background: #11141a; color: var(--text); }
  input:focus { outline: none; border-color: #4f8cff; }
  button { width: 100%; margin-top: 1.1rem; background: var(--accent-grad); color: #0f1115; border: none;
    border-radius: 8px; padding: 0.55rem; font-size: 0.9rem; font-weight: 600; cursor: pointer; }
  .error { margin-top: 0.75rem; padding: 0.5rem 0.7rem; border-radius: 8px; font-size: 0.85rem;
    background: rgba(255,107,107,0.12); color: var(--danger); }
  .muted { color: var(--text-muted); font-size: 0.82rem; }
  code { background: #11141a; padding: 0.1rem 0.35rem; border-radius: 4px; font-size: 0.85em; }
</style>
</head>
<body>
<div class="box">
  <div class="title"><img src="/mark.svg" alt=""><h1>Backup Buddies</h1></div>
"#;

fn login_html(error: Option<&str>) -> String {
    let error = error.map(|e| format!(r#"<div class="error">{e}</div>"#)).unwrap_or_default();
    format!(
        r#"{PAGE_HEAD}  <form method="post" action="/login">
    <label>User name<input name="username" autocomplete="username" value="admin" required></label>
    <label>Password<input name="password" type="password" autocomplete="current-password" required autofocus></label>
    {error}
    <button type="submit">Log in</button>
  </form>
  <p class="muted">Set with <code>DASHBOARD_USER</code> and <code>DASHBOARD_PASSWORD</code> in this device's
    <code>.env</code>.</p>
</div>
</body>
</html>
"#
    )
}

fn local_only_page() -> String {
    format!(
        r#"{PAGE_HEAD}  <p>This dashboard has no password yet, so it only opens on the machine running the client
    (<code>http://localhost:&lt;port&gt;</code>).</p>
  <p class="muted">To open it from other devices, add a password to the client's <code>.env</code>, then
    restart it with <code>docker compose up -d</code>:</p>
  <p><code>DASHBOARD_PASSWORD=choose-a-long-one</code></p>
  <p class="muted">You'll log in as <code>admin</code> (change it with <code>DASHBOARD_USER</code>).</p>
</div>
</body>
</html>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn login(user: &str, password: &str) -> Login {
        Login { user_hash: sha256(user), password_hash: sha256(password) }
    }

    #[test]
    fn checks_user_and_password() {
        let l = login("admin", "correct horse");
        assert!(l.matches("admin", "correct horse"));
        assert!(l.matches(" admin ", "correct horse"));
        assert!(!l.matches("admin", "correct horse "));
        assert!(!l.matches("root", "correct horse"));
    }

    #[test]
    fn sessions_and_cookies() {
        let auth = Auth::new(Some(login("admin", "pw")), "0.0.0.0:8081");
        let token = auth.new_session();
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(&format!("other=1; bb_session_8081={token}")).unwrap());
        assert!(auth.has_session(&headers));

        // Another port's dashboard on the same host has its own cookie.
        let other = Auth::new(Some(login("admin", "pw")), "0.0.0.0:8080");
        assert!(!other.has_session(&headers));

        headers.insert(header::COOKIE, HeaderValue::from_static("bb_session_8081=made-up"));
        assert!(!auth.has_session(&headers));
    }

    #[test]
    fn locks_out_after_repeated_failures() {
        let auth = Auth::new(Some(login("admin", "pw")), "0.0.0.0:8080");
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        for _ in 0..MAX_FAILURES - 1 {
            auth.note_failure(ip);
        }
        assert!(auth.locked_out(ip).is_none());
        auth.note_failure(ip);
        assert!(auth.locked_out(ip).is_some());
        assert!(auth.locked_out("192.168.1.51".parse().unwrap()).is_none());
    }

    #[test]
    fn cross_origin_posts_are_spotted() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("192.168.1.5:8080"));
        assert!(!cross_origin(&h), "no Origin header: not a browser cross-site request");
        h.insert(header::ORIGIN, HeaderValue::from_static("http://192.168.1.5:8080"));
        assert!(!cross_origin(&h));
        h.insert(header::ORIGIN, HeaderValue::from_static("http://192.168.1.5:9000"));
        assert!(cross_origin(&h), "another app on the same NAS");
    }

    /// Serves a stand-in page behind the real middleware and login routes
    /// on a random local port.
    async fn serve(login: Option<Login>) -> String {
        use axum::routing::{get, post};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let auth = Auth::new(login, &addr.to_string());
        let app = axum::Router::new()
            .route("/", get(|| async { "dashboard" }))
            .route("/api/restore", post(|| async { "restored" }))
            .route("/login", get(login_page).post(login_submit))
            .route("/logout", post(logout))
            .with_state(auth.clone())
            .layer(axum::middleware::from_fn_with_state(auth, require_login));
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap()
    }

    async fn post_form(c: &reqwest::Client, base: &str, body: &'static str) -> reqwest::Response {
        c.post(format!("{base}/login"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn login_flow_over_http() {
        let base = serve(Some(login("admin", "hunter22hunter22"))).await;
        let c = client();

        let res = c.get(&base).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers()[header::LOCATION], "/login");
        let res = c.post(format!("{base}/api/restore")).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let res = post_form(&c, &base, "username=admin&password=nope").await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let res = post_form(&c, &base, "username=admin&password=hunter22hunter22").await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let set_cookie = res.headers()[header::SET_COOKIE].to_str().unwrap().to_string();
        assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Strict"), "{set_cookie}");
        let cookie = set_cookie.split(';').next().unwrap().to_string();

        let res = c.get(&base).header(header::COOKIE, &cookie).send().await.unwrap();
        assert_eq!(res.text().await.unwrap(), "dashboard");

        // Logged in, but posted from another site's page: refused.
        let res = c
            .post(format!("{base}/api/restore"))
            .header(header::COOKIE, &cookie)
            .header(header::ORIGIN, "http://evil.example")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let res = c.post(format!("{base}/api/restore")).header(header::COOKIE, &cookie).send().await.unwrap();
        assert_eq!(res.text().await.unwrap(), "restored");

        let res = c.post(format!("{base}/logout")).header(header::COOKIE, &cookie).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let res = c.get(&base).header(header::COOKIE, &cookie).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "the session ends at logout");
    }

    #[tokio::test]
    async fn without_a_password_only_this_machine_gets_in() {
        let base = serve(None).await;
        let c = client();
        let res = c.get(&base).send().await.unwrap();
        assert_eq!(res.text().await.unwrap(), "dashboard", "127.0.0.1 is let in");

        // DNS rebinding: a request from this machine's browser, but for a
        // page on some other name that resolves here.
        let res = c.get(&base).header(header::HOST, "evil.example").send().await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert!(res.text().await.unwrap().contains("DASHBOARD_PASSWORD"));
    }

    #[test]
    fn host_names() {
        assert_eq!(host_name("localhost:8080"), "localhost");
        assert_eq!(host_name("127.0.0.1"), "127.0.0.1");
        assert_eq!(host_name("[::1]:8080"), "::1");
    }
}
