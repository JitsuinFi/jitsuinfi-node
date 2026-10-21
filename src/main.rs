//! jitsuin-node: a financier's node (HNK-26). This first part sets the node up on testnet
//! (HNK-26.T1), serves its public identity, and registers the financier mailbox at the relay
//! (HNK-26.T4); the deal API and the console follow.
//!
//! Runs behind Railway's HTTPS edge, which forwards plain HTTP to PORT inside the container.

mod board;
mod config;
mod console;
mod keys;
mod mail;
mod message;
mod relay;
mod setup;

use std::sync::Arc;

use axum::extract::{Path, State as AxState};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tower_http::set_header::SetResponseHeaderLayer;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// What anyone may know about this node: no secret, no balance.
struct Public {
    network: String,
    financier_pk: String,
    mailbox_pk: String,
    mailbox_id: String,
    wallet_address: String,
    contact: String,
}

fn public(cfg: &config::Config, node: &setup::Node) -> Public {
    let mb = node.keys.mailbox();
    let fin = node.keys.financier().verifying_key().to_bytes();
    Public {
        network: cfg.network.clone(),
        financier_pk: hex(&fin),
        contact: relay::contact_card(&mb.public(), &fin),
        mailbox_pk: hex(&mb.public()),
        mailbox_id: hex(&mb.id()),
        wallet_address: node.wallet_address.clone(),
    }
}

/// The console's static files, built into the binary (no file serving from disk).
fn asset(path: &str) -> Option<(&'static str, &'static [u8])> {
    Some(match path {
        "" => (
            "text/html; charset=utf-8",
            include_bytes!("../console/index.html"),
        ),
        "pair" => (
            "text/html; charset=utf-8",
            include_bytes!("../console/pair.html"),
        ),
        "passkey.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("../console/passkey.js"),
        ),
        "console.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("../console/console.js"),
        ),
        "pair.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("../console/pair.js"),
        ),
        "console.css" => (
            "text/css; charset=utf-8",
            include_bytes!("../console/console.css"),
        ),
        "fonts/geist.woff2" => ("font/woff2", include_bytes!("../console/fonts/geist.woff2")),
        "fonts/geist-mono.woff2" => (
            "font/woff2",
            include_bytes!("../console/fonts/geist-mono.woff2"),
        ),
        _ => return None,
    })
}

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

#[derive(Clone)]
struct State {
    public: Arc<Public>,
    console: Option<Arc<console::Console>>,
    origin: Option<String>,
    mail: Arc<mail::Mail>,
    board: Arc<board::Board>,
}

impl State {
    /// The console, for a request from the console's own origin only (no cross-site POST).
    fn console(
        &self,
        headers: &HeaderMap,
    ) -> Result<&console::Console, (StatusCode, &'static str)> {
        let (Some(c), Some(origin)) = (&self.console, &self.origin) else {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "the console is off: set NODE_ORIGIN",
            ));
        };
        if headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(origin.as_str()) {
            return Err((
                StatusCode::FORBIDDEN,
                "requests must come from the console page",
            ));
        }
        Ok(c)
    }
}

impl State {
    /// A request with an open console session; `write` also needs the console's own `Origin`.
    fn signed_in(
        &self,
        headers: &HeaderMap,
        write: bool,
    ) -> Result<(), (StatusCode, &'static str)> {
        let c = if write {
            self.console(headers)?
        } else {
            self.console.as_deref().ok_or((
                StatusCode::SERVICE_UNAVAILABLE,
                "the console is off: set NODE_ORIGIN",
            ))?
        };
        match session_token(headers) {
            Some(t) if c.session(t) => Ok(()),
            _ => Err((StatusCode::UNAUTHORIZED, "sign in to the console first")),
        }
    }
}

async fn mail_list(AxState(st): AxState<State>, headers: HeaderMap) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, false) {
        return error(status, msg);
    }
    match st.mail.list().await {
        Ok((messages, refused)) => {
            Json(json!({ "messages": messages, "refused": refused })).into_response()
        }
        Err(e) => error(StatusCode::BAD_GATEWAY, &e.to_string()),
    }
}

async fn mail_attachment(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Path((id, index)): Path<(String, usize)>,
) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, false) {
        return error(status, msg);
    }
    match st.mail.attachment(&id, index) {
        Some((name, bytes)) => (
            [
                (header::CONTENT_TYPE, "application/pdf".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"", mail::safe_name(&name)),
                ),
            ],
            bytes,
        )
            .into_response(),
        None => error(
            StatusCode::NOT_FOUND,
            "list the mailbox again; this attachment is not in it",
        ),
    }
}

async fn mail_remove(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, true) {
        return error(status, msg);
    }
    match st.mail.remove(&id).await {
        Ok(true) => Json(json!({ "ok": true })).into_response(),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            "list the mailbox again; this message is not in it",
        ),
        Err(e) => error(StatusCode::BAD_GATEWAY, &e.to_string()),
    }
}

fn pair_status(e: &console::PairError) -> StatusCode {
    use console::PairError::*;
    match e {
        NoCode | Expired | Ceremony | LoginGone => StatusCode::GONE,
        NotPaired => StatusCode::CONFLICT,
        Wrong | Rejected => StatusCode::FORBIDDEN,
        Full => StatusCode::CONFLICT,
        Store => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn pair_start(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let c = match st.console(&headers) {
        Ok(c) => c,
        Err((status, msg)) => return error(status, msg),
    };
    let Some(code) = body["code"].as_str().filter(|c| c.len() <= 64) else {
        return error(StatusCode::BAD_REQUEST, "code is missing");
    };
    match c.start(code) {
        Ok((ceremony, options)) => {
            Json(json!({ "ceremony": ceremony, "options": options })).into_response()
        }
        Err(e) => error(pair_status(&e), e.message()),
    }
}

async fn pair_finish(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let c = match st.console(&headers) {
        Ok(c) => c,
        Err((status, msg)) => return error(status, msg),
    };
    let (Some(ceremony), Ok(credential)) = (
        body["ceremony"].as_str(),
        serde_json::from_value(body["credential"].clone()),
    ) else {
        return error(StatusCode::BAD_REQUEST, "ceremony or credential is missing");
    };
    match c.finish(ceremony, &credential) {
        Ok(n) => {
            println!("console: passkey paired ({n} kept)");
            Json(json!({ "ok": true, "credentials": n })).into_response()
        }
        Err(e) => error(pair_status(&e), e.message()),
    }
}

/// The session token from the `__Host-` cookie, if any.
fn session_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().strip_prefix(console::COOKIE)?.strip_prefix('='))
}

fn session_cookie(token: &str, max_age: u64) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={max_age}",
        console::COOKIE
    ))
    .expect("cookie")
}

async fn login_start(AxState(st): AxState<State>, headers: HeaderMap) -> Response {
    let c = match st.console(&headers) {
        Ok(c) => c,
        Err((status, msg)) => return error(status, msg),
    };
    match c.login_start() {
        Ok((ceremony, options)) => {
            Json(json!({ "ceremony": ceremony, "options": options })).into_response()
        }
        Err(e) => error(pair_status(&e), e.message()),
    }
}

async fn login_finish(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let c = match st.console(&headers) {
        Ok(c) => c,
        Err((status, msg)) => return error(status, msg),
    };
    let (Some(ceremony), Ok(credential)) = (
        body["ceremony"].as_str(),
        serde_json::from_value(body["credential"].clone()),
    ) else {
        return error(StatusCode::BAD_REQUEST, "ceremony or credential is missing");
    };
    match c.login_finish(ceremony, &credential) {
        Ok(token) => (
            [(
                header::SET_COOKIE,
                session_cookie(&token, console::SESSION_TTL.as_secs()),
            )],
            Json(json!({ "ok": true })),
        )
            .into_response(),
        Err(e) => error(pair_status(&e), e.message()),
    }
}

async fn session(AxState(st): AxState<State>, headers: HeaderMap) -> Response {
    let open = st
        .console
        .as_ref()
        .zip(session_token(&headers))
        .is_some_and(|(c, t)| c.session(t));
    let paired = st.console.as_ref().is_some_and(|c| !c.stored().is_empty());
    Json(json!({ "signed_in": open, "paired": paired, "console": st.console.is_some() }))
        .into_response()
}

async fn logout(AxState(st): AxState<State>, headers: HeaderMap) -> Response {
    let c = match st.console(&headers) {
        Ok(c) => c,
        Err((status, msg)) => return error(status, msg),
    };
    if let Some(t) = session_token(&headers) {
        c.logout(t);
    }
    (
        [(header::SET_COOKIE, session_cookie("", 0))],
        Json(json!({ "ok": true })),
    )
        .into_response()
}

/// The board as the node last scanned it (public data: anyone holding the board UFVK sees it).
async fn board_snapshot(AxState(st): AxState<State>) -> Response {
    match st.board.latest() {
        Some(v) => Json(v).into_response(),
        None => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "the node is still scanning the board",
        ),
    }
}

async fn console_file(Path(path): Path<String>) -> Response {
    match asset(&path) {
        Some((mime, bytes)) => ([(header::CONTENT_TYPE, mime)], bytes).into_response(),
        None => error(StatusCode::NOT_FOUND, "not found"),
    }
}

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

fn app(st: State) -> Router {
    let info = {
        let p = st.public.clone();
        move || async move {
            Json(json!({
                "network": p.network,
                "financier_pk": p.financier_pk,
                "mailbox_pk": p.mailbox_pk,
                "mailbox_id": p.mailbox_id,
                "wallet_address": p.wallet_address,
                "contact": p.contact,
            }))
        }
    };
    Router::new()
        .route(
            "/node/health",
            get(|| async { Json::<Value>(json!({ "ok": true })) }),
        )
        .route("/node/info", get(info))
        .route("/node/console/pair/start", post(pair_start))
        .route("/node/console/pair/finish", post(pair_finish))
        .route("/node/console/login/start", post(login_start))
        .route("/node/console/login/finish", post(login_finish))
        .route("/node/console/session", get(session))
        .route("/node/console/logout", post(logout))
        .route("/node/board", get(board_snapshot))
        .route("/node/mail", get(mail_list))
        .route("/node/mail/{id}", delete(mail_remove))
        .route("/node/mail/{id}/attachments/{index}", get(mail_attachment))
        .route("/console/", get(|| console_file(Path(String::new()))))
        .route(
            "/console",
            get(|| async { Redirect::permanent("/console/") }),
        )
        .route("/console/{*path}", get(console_file))
        .with_state(st)
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
}

fn fail(e: impl std::fmt::Display) -> ! {
    eprintln!("{e}");
    std::process::exit(1)
}

/// Registers the mailbox at the relay, retrying with backoff: the node serves its identity even
/// while the relay is down, and the deal API refuses work until this succeeds (next task).
async fn register_mailbox(relay_url: String, me: jitsuin_core::mailbox::MailboxKeys) {
    let relay = match relay::Relay::new(&relay_url) {
        Ok(r) => r,
        Err(e) => return eprintln!("relay: {e}"),
    };
    let mut wait = 5;
    loop {
        match relay.ensure_mailbox(&me).await {
            Ok(()) => return println!("relay: mailbox registered at {relay_url}"),
            Err(e) => eprintln!("relay: {e}; retrying in {wait} s"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        wait = (wait * 2).min(600);
    }
}

#[tokio::main]
async fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "serve".into());
    let cfg = match config::Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            std::process::exit(2);
        }
    };
    let (node, made) = match tokio::task::spawn_blocking({
        let cfg = cfg.clone();
        move || setup::setup(&cfg)
    })
    .await
    .expect("setup task")
    {
        Ok(x) => x,
        Err(e) => {
            eprintln!("setup: {e}");
            std::process::exit(1);
        }
    };
    let p = public(&cfg, &node);
    if !made.is_empty() {
        println!("setup: created {}", made.join(", "));
    }
    println!(
        "financier_pk {}\nmailbox_id {}\nwallet {}",
        p.financier_pk, p.mailbox_id, p.wallet_address
    );
    match cmd.as_str() {
        "setup" | "info" => {}
        "pair" => {
            let code = console::new_code(&cfg.data_dir).unwrap_or_else(|e| fail(e));
            println!(
                "pairing code {code}\nvalid for {} minutes, once; type it on {}/console/pair",
                console::CODE_TTL.as_secs() / 60,
                cfg.node_origin
                    .as_deref()
                    .unwrap_or("the node's console (set NODE_ORIGIN)")
            );
        }
        "inbox" => {
            let relay = relay::Relay::new(&cfg.relay_url).unwrap_or_else(|e| fail(e));
            let me = node.keys.mailbox();
            relay.ensure_mailbox(&me).await.unwrap_or_else(|e| fail(e));
            let (got, refused, _) = relay.receive(&me).await.unwrap_or_else(|e| fail(e));
            for r in &got {
                let h = &r.message.header;
                println!(
                    "{} {} from {} n={} signature={} attachments={} at {}",
                    r.relay_id,
                    h["type"].as_str().unwrap_or("?"),
                    h["from"]["role"].as_str().unwrap_or("?"),
                    h["n"].as_str().unwrap_or("-"),
                    if r.signature_ok { "ok" } else { "BAD" },
                    r.message.attachments.len(),
                    r.received_at
                );
            }
            println!("{} message(s), {refused} refused", got.len());
        }
        "serve" => {
            tokio::spawn(register_mailbox(cfg.relay_url.clone(), node.keys.mailbox()));
            let listener = tokio::net::TcpListener::bind(("0.0.0.0", cfg.port))
                .await
                .expect("bind PORT");
            println!("node listening on :{}", cfg.port);
            let console = cfg.node_origin.as_deref().and_then(|o| {
                console::Console::new(o, &cfg.data_dir, node.keys.console_user())
                    .map_err(|e| eprintln!("console off: {e}"))
                    .ok()
                    .map(Arc::new)
            });
            if console.is_none() && cfg.node_origin.is_none() {
                println!("console off: NODE_ORIGIN is not set");
            }
            let relay = relay::Relay::new(&cfg.relay_url).unwrap_or_else(|e| fail(e));
            let board = Arc::new(board::Board::default());
            tokio::spawn(
                board
                    .clone()
                    .run(node.board_watch.clone(), cfg.lightwalletd.clone()),
            );
            let st = State {
                board,
                public: Arc::new(p),
                console,
                origin: cfg.node_origin.clone(),
                mail: Arc::new(mail::Mail::new(relay, node.keys.mailbox())),
            };
            axum::serve(listener, app(st))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
                .expect("serve");
        }
        other => {
            eprintln!("unknown command {other}: use setup, info, pair, inbox or serve");
            std::process::exit(2);
        }
    }
}
