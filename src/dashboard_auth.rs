// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! Login for the local dashboard.
//!
//! The dashboard can restore decrypted files and edit the exclude list
//! (which removes files from buddies), so every page needs a login, from
//! any address:
//!
//! - The first login is DASHBOARD_USER (default `admin`) and
//!   DASHBOARD_PASSWORD from .env.
//! - After that the password can be changed from the dashboard itself. The
//!   new one is kept, hashed, in DATA_DIR/dashboard-login and replaces the
//!   .env one; deleting that file goes back to .env (the reset).
//! - With no DASHBOARD_PASSWORD and no changed password, the dashboard
//!   stays locked and says to set one. There's no default password: one
//!   that works until someone changes it works for whoever on the network
//!   tries it first.
//!
//! Sessions are a random token in a cookie, kept in memory: a restart logs
//! everyone out.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const STORED_FILE: &str = "dashboard-login";
const SESSION_LIFETIME: Duration = Duration::from_secs(30 * 24 * 3600);
// After this many wrong passwords in a row from one address, it has to
// wait LOCKOUT before trying again.
const MAX_FAILURES: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(60);
const MIN_PASSWORD_LEN: usize = 8;
// scrypt cost for the stored password: ~50 ms a check, enough to make an
// offline guess at a copied file slow without making logins sluggish.
const HASH_LOG_N: u8 = 15;

/// A user name and a salted scrypt hash of the password. The same form for
/// the .env password (hashed at startup) and a changed one (saved to
/// STORED_FILE), so there's one way to check either.
#[derive(Clone, Serialize, Deserialize)]
struct Login {
    user: String,
    salt: String,
    hash: String,
}

fn hash_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let params = scrypt::Params::new(HASH_LOG_N, 8, 1, 32).expect("valid scrypt params");
    let mut out = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut out).expect("32 bytes is a valid scrypt output length");
    out
}

fn sha256(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(Sha256::digest(text.as_bytes()).as_slice());
    out
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Login {
    fn new(user: &str, password: &str) -> Self {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).expect("the OS random number generator is unavailable");
        Login { user: user.to_string(), salt: hex::encode(salt), hash: hex::encode(hash_password(password, &salt)) }
    }

    fn matches(&self, user: &str, password: &str) -> bool {
        let salt = hex::decode(&self.salt).unwrap_or_default();
        let hash = hex::decode(&self.hash).unwrap_or_default();
        // Both checked every time, so a right user name isn't faster.
        let user_ok = same(&sha256(&self.user), &sha256(user.trim()));
        let password_ok = same(&hash, &hash_password(password, &salt));
        user_ok & password_ok
    }
}

/// Where the login in use came from — the startup log and the
/// change-password dialog say which.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Source {
    Env,
    Changed,
}

/// The .env login, if DASHBOARD_PASSWORD is set and not empty.
fn env_login() -> Option<Login> {
    let password = std::env::var("DASHBOARD_PASSWORD").ok().filter(|p| !p.is_empty())?;
    if password.len() < MIN_PASSWORD_LEN {
        tracing::warn!("DASHBOARD_PASSWORD is under {MIN_PASSWORD_LEN} characters — anyone on your network can try guesses at it");
    }
    let user = std::env::var("DASHBOARD_USER")
        .ok()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| "admin".to_string());
    Some(Login::new(&user, &password))
}

/// A password changed on the dashboard wins over .env's; an unreadable
/// file is logged and ignored (so .env's still lets the person in).
fn load_login(data_dir: &Path) -> Option<(Login, Source)> {
    let path = data_dir.join(STORED_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str::<Login>(&text) {
            Ok(login) => return Some((login, Source::Changed)),
            Err(err) => tracing::warn!(path = %path.display(), %err, "ignoring an unreadable dashboard-login file"),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => tracing::warn!(path = %path.display(), %err, "can't read the dashboard-login file"),
    }
    env_login().map(|login| (login, Source::Env))
}

#[derive(Clone)]
pub struct Auth {
    inner: Arc<Inner>,
}

struct Inner {
    data_dir: PathBuf,
    login: Mutex<Option<(Login, Source)>>,
    // Per port, so two clients' dashboards on one host (each on its own
    // DASHBOARD_PORT) don't overwrite each other's session: cookies are
    // shared across ports.
    cookie_name: String,
    sessions: Mutex<HashMap<String, Instant>>,
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl Auth {
    pub fn new(data_dir: &Path, bind_addr: &str) -> Self {
        let port = bind_addr.rsplit(':').next().filter(|p| p.parse::<u16>().is_ok());
        let cookie_name = match port {
            Some(port) => format!("bb_session_{port}"),
            None => "bb_session".to_string(),
        };
        let login = load_login(data_dir);
        match login.as_ref().map(|(_, source)| *source) {
            Some(Source::Env) => tracing::info!("dashboard login: DASHBOARD_USER / DASHBOARD_PASSWORD from .env"),
            Some(Source::Changed) => tracing::info!(
                "dashboard login: the password changed on the dashboard (delete {STORED_FILE} in the config folder \
                 to go back to DASHBOARD_PASSWORD from .env)"
            ),
            None => tracing::warn!(
                "no DASHBOARD_PASSWORD set — the dashboard stays locked until you add one to .env and restart"
            ),
        }
        Auth {
            inner: Arc::new(Inner {
                data_dir: data_dir.to_path_buf(),
                login: Mutex::new(login),
                cookie_name,
                sessions: Mutex::new(HashMap::new()),
                failures: Mutex::new(HashMap::new()),
            }),
        }
    }

    fn login(&self) -> Option<(Login, Source)> {
        self.inner.login.lock().unwrap().clone()
    }

    /// The login's scrypt check, off the async threads.
    async fn check(&self, user: String, password: String) -> bool {
        let Some((login, _)) = self.login() else { return false };
        tokio::task::spawn_blocking(move || login.matches(&user, &password)).await.unwrap_or(false)
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

    /// Saves `login` as the changed password (written to a temporary file
    /// and renamed, owner-only) and switches to it.
    async fn save_changed(&self, login: Login) -> anyhow::Result<()> {
        use anyhow::Context;
        let path = self.inner.data_dir.join(STORED_FILE);
        let tmp = path.with_extension("saving");
        let text = serde_json::to_string(&login)?;
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&tmp).await.with_context(|| format!("can't write {}", tmp.display()))?;
        tokio::io::AsyncWriteExt::write_all(&mut file, text.as_bytes()).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&tmp, &path).await.with_context(|| format!("can't replace {}", path.display()))?;
        *self.inner.login.lock().unwrap() = Some((login, Source::Changed));
        Ok(())
    }
}

/// Pages that work without a login: the login form itself and the icons
/// it shows.
fn is_public(path: &str) -> bool {
    matches!(path, "/login" | "/favicon.svg" | "/mark.svg")
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
pub async fn require_login(State(auth): State<Auth>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    if req.method() != Method::GET && req.method() != Method::HEAD && cross_origin(headers) {
        return (StatusCode::FORBIDDEN, "Cross-site request refused").into_response();
    }
    let path = req.uri().path();
    if matches!(path, "/favicon.svg" | "/mark.svg") {
        return next.run(req).await;
    }
    if auth.login().is_none() {
        return (StatusCode::FORBIDDEN, Html(no_password_page())).into_response();
    }
    if is_public(path) || auth.has_session(headers) {
        return next.run(req).await;
    }
    if path.starts_with("/api/") {
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
    let ip = peer.ip().to_canonical();
    if let Some(wait) = auth.locked_out(ip) {
        let msg = format!("Too many wrong passwords. Try again in {wait} seconds.");
        return (StatusCode::TOO_MANY_REQUESTS, Html(login_html(Some(&msg)))).into_response();
    }
    if !auth.check(form.username, form.password).await {
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

#[derive(Deserialize)]
pub struct PasswordChange {
    current: String,
    new: String,
}

/// POST /api/password (behind the login like every other /api route). The
/// current password is asked for again, so a session left open on someone
/// else's screen can't be used to lock the owner out. Other sessions are
/// logged out; this one stays.
pub async fn change_password(
    State(auth): State<Auth>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PasswordChange>,
) -> Response {
    let ip = peer.ip().to_canonical();
    if let Some(wait) = auth.locked_out(ip) {
        return (StatusCode::TOO_MANY_REQUESTS, format!("Too many wrong passwords. Try again in {wait} seconds."))
            .into_response();
    }
    let Some((login, _)) = auth.login() else {
        return (StatusCode::FORBIDDEN, "No login is set up").into_response();
    };
    if !auth.check(login.user.clone(), body.current).await {
        auth.note_failure(ip);
        return (StatusCode::BAD_REQUEST, "Your current password isn't right.").into_response();
    }
    if body.new.chars().count() < MIN_PASSWORD_LEN {
        return (StatusCode::BAD_REQUEST, format!("Use at least {MIN_PASSWORD_LEN} characters.")).into_response();
    }
    let user = login.user.clone();
    let new_login = match tokio::task::spawn_blocking(move || Login::new(&user, &body.new)).await {
        Ok(login) => login,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Couldn't hash the new password").into_response(),
    };
    if let Err(err) = auth.save_changed(new_login).await {
        tracing::warn!(?err, "couldn't save the new dashboard password");
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't save it: {err:#}")).into_response();
    }
    let keep = auth.session_from(&headers);
    auth.inner.sessions.lock().unwrap().retain(|token, _| Some(token) == keep.as_ref());
    tracing::info!(from = %ip, "dashboard password changed");
    StatusCode::NO_CONTENT.into_response()
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
  <p class="muted">The first time, use <code>DASHBOARD_PASSWORD</code> from this device's <code>.env</code>
    (user <code>admin</code> unless <code>DASHBOARD_USER</code> is set). You can change it once you're in.</p>
</div>
</body>
</html>
"#
    )
}

fn no_password_page() -> String {
    format!(
        r#"{PAGE_HEAD}  <p>This dashboard doesn't have a password yet.</p>
  <p class="muted">Add one to the client's <code>.env</code>, then restart it with
    <code>docker compose up -d</code>:</p>
  <p><code>DASHBOARD_PASSWORD=choose-a-long-one</code></p>
  <p class="muted">Log in as <code>admin</code> with it. You can change the password from the dashboard after
    that.</p>
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

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bb-test-auth-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An Auth for a fixed login, without touching .env or the disk.
    fn auth_with(user: &str, password: &str, data_dir: &Path, port: u16) -> Auth {
        let auth = Auth::new(data_dir, &format!("0.0.0.0:{port}"));
        *auth.inner.login.lock().unwrap() = Some((Login::new(user, password), Source::Env));
        auth
    }

    #[test]
    fn checks_user_and_password() {
        let l = Login::new("admin", "correct horse");
        assert!(l.matches("admin", "correct horse"));
        assert!(l.matches(" admin ", "correct horse"));
        assert!(!l.matches("admin", "correct horse "));
        assert!(!l.matches("root", "correct horse"));
        assert_ne!(Login::new("admin", "correct horse").hash, l.hash, "salted");
    }

    #[test]
    fn sessions_and_cookies() {
        let dir = tmp("sessions");
        let auth = auth_with("admin", "pw", &dir, 8081);
        let token = auth.new_session();
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(&format!("other=1; bb_session_8081={token}")).unwrap());
        assert!(auth.has_session(&headers));

        // Another port's dashboard on the same host has its own cookie.
        let other = auth_with("admin", "pw", &dir, 8080);
        assert!(!other.has_session(&headers));

        headers.insert(header::COOKIE, HeaderValue::from_static("bb_session_8081=made-up"));
        assert!(!auth.has_session(&headers));
    }

    #[test]
    fn locks_out_after_repeated_failures() {
        let auth = auth_with("admin", "pw", &tmp("lockout"), 8080);
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
    async fn serve(auth_for: impl FnOnce(u16) -> Auth) -> (String, Auth) {
        use axum::routing::{get, post};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let auth = auth_for(addr.port());
        let app = axum::Router::new()
            .route("/", get(|| async { "dashboard" }))
            .route("/api/restore", post(|| async { "restored" }))
            .route("/api/password", post(change_password))
            .route("/login", get(login_page).post(login_submit))
            .route("/logout", post(logout))
            .with_state(auth.clone())
            .layer(axum::middleware::from_fn_with_state(auth.clone(), require_login));
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
        });
        (format!("http://{addr}"), auth)
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap()
    }

    async fn log_in(c: &reqwest::Client, base: &str, password: &str) -> Option<String> {
        let res = c
            .post(format!("{base}/login"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("username=admin&password={password}"))
            .send()
            .await
            .unwrap();
        let cookie = res.headers().get(header::SET_COOKIE)?.to_str().unwrap().to_string();
        assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"), "{cookie}");
        Some(cookie.split(';').next().unwrap().to_string())
    }

    #[tokio::test]
    async fn login_flow_over_http() {
        let dir = tmp("http");
        let (base, _) = serve(|port| auth_with("admin", "hunter22hunter22", &dir, port)).await;
        let c = client();

        let res = c.get(&base).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers()[header::LOCATION], "/login");
        let res = c.post(format!("{base}/api/restore")).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        assert!(log_in(&c, &base, "nope").await.is_none());
        let cookie = log_in(&c, &base, "hunter22hunter22").await.unwrap();

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
    async fn password_changed_on_the_dashboard_replaces_the_env_one() {
        let dir = tmp("change");
        let (base, _) = serve(|port| auth_with("admin", "from-the-env-file", &dir, port)).await;
        let c = client();
        let cookie = log_in(&c, &base, "from-the-env-file").await.unwrap();
        let other_session = log_in(&c, &base, "from-the-env-file").await.unwrap();

        let change = |current: &str, new: &str| {
            c.post(format!("{base}/api/password"))
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(serde_json::json!({ "current": current, "new": new }).to_string())
                .send()
        };
        assert_eq!(change("wrong", "a-new-password").await.unwrap().status(), StatusCode::BAD_REQUEST);
        assert_eq!(change("from-the-env-file", "short").await.unwrap().status(), StatusCode::BAD_REQUEST);
        assert_eq!(change("from-the-env-file", "a-new-password").await.unwrap().status(), StatusCode::NO_CONTENT);

        // This session carries on, other sessions are logged out, and only
        // the new password works now.
        let res = c.get(&base).header(header::COOKIE, &cookie).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let res = c.get(&base).header(header::COOKIE, &other_session).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert!(log_in(&c, &base, "from-the-env-file").await.is_none());
        assert!(log_in(&c, &base, "a-new-password").await.is_some());

        // Saved hashed, and used after a restart in place of .env's.
        let saved = std::fs::read_to_string(dir.join(STORED_FILE)).unwrap();
        assert!(!saved.contains("a-new-password"));
        let (login, source) = load_login(&dir).unwrap();
        assert_eq!(source, Source::Changed);
        assert!(login.matches("admin", "a-new-password"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn without_any_password_it_stays_locked() {
        let dir = tmp("none");
        let (base, _) = serve(|port| {
            let auth = Auth::new(&dir, &format!("0.0.0.0:{port}"));
            *auth.inner.login.lock().unwrap() = None;
            auth
        })
        .await;
        let c = client();
        let res = c.get(&base).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "not even from 127.0.0.1");
        assert!(res.text().await.unwrap().contains("DASHBOARD_PASSWORD"));
        assert!(log_in(&c, &base, "anything").await.is_none());
    }
}
