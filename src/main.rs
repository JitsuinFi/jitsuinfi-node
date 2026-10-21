//! jitsuin-node: a financier's node (HNK-26). This first part sets the node up on testnet
//! (HNK-26.T1), serves its public identity, and registers the financier mailbox at the relay
//! (HNK-26.T4); the deal API and the console follow.
//!
//! Runs behind Railway's HTTPS edge, which forwards plain HTTP to PORT inside the container.

mod board;
mod buyers;
mod config;
mod console;
mod keys;
mod mail;
mod message;
mod offer;
mod pay;
mod provider;
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
    data_dir: std::path::PathBuf,
    /// The financier's display name, shown only in its own console: what the financier saved
    /// (`financier-name.txt` in the volume), else FINANCIER_NAME from the provider.
    name: Arc<std::sync::RwLock<Option<String>>>,
    /// Signs the node's replies in a deal (commitment opening, letter, advance).
    financier: Arc<ed25519_dalek::SigningKey>,
    /// Buyers the financier knows from KYC (HNK-26.T7).
    buyers: Arc<buyers::Registry>,
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

const NAME_FILE: &str = "financier-name.txt";

/// A display name: printable, at most 60 characters, trimmed; `None` when empty.
fn clean_name(n: &str) -> Option<String> {
    let n: String = n.chars().filter(|c| !c.is_control()).take(60).collect();
    let n = n.trim().to_string();
    (!n.is_empty()).then_some(n)
}

impl State {
    fn name(&self) -> Option<String> {
        self.name.read().unwrap().clone()
    }

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

/// The financier sets its own display name from a signed-in console.
async fn set_name(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, true) {
        return error(status, msg);
    }
    if st.console.as_ref().is_some_and(|c| c.demo) {
        return error(
            StatusCode::FORBIDDEN,
            "this is the demo console: that is turned off here",
        );
    }
    let Some(name) = body["name"].as_str().and_then(clean_name) else {
        return error(StatusCode::BAD_REQUEST, "type a name");
    };
    if std::fs::write(st.data_dir.join(NAME_FILE), &name).is_err() {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the node could not save the name",
        );
    }
    *st.name.write().unwrap() = Some(name.clone());
    Json(json!({ "ok": true, "name": name })).into_response()
}

/// "Add a device": a one-time pairing code (15 minutes) and its invite link, from a signed-in
/// console; no terminal (HNK-26.T20, D-43).
async fn device_code(AxState(st): AxState<State>, headers: HeaderMap) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, true) {
        return error(status, msg);
    }
    if st.console.as_ref().is_some_and(|c| c.demo) {
        return error(
            StatusCode::FORBIDDEN,
            "this is the demo console: that is turned off here",
        );
    }
    let origin = st.origin.clone().unwrap_or_default();
    match console::new_code(&st.data_dir) {
        Ok(code) => Json(json!({
            "code": code,
            "link": format!("{origin}/console/pair#{code}"),
            "expires_in": console::CODE_TTL.as_secs(),
        }))
        .into_response(),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the node could not make a code",
        ),
    }
}

/// The paired passkeys: when paired, last used, usable on this origin, the session's own.
async fn devices_list(AxState(st): AxState<State>, headers: HeaderMap) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, false) {
        return error(status, msg);
    }
    let c = st.console.as_deref().expect("signed in implies a console");
    let token = session_token(&headers).unwrap_or_default();
    Json(json!({ "devices": c.devices(token) })).into_response()
}

/// Removes a paired passkey (never the session's own).
async fn device_remove(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, true) {
        return error(status, msg);
    }
    let c = st.console.as_deref().expect("signed in implies a console");
    match c.remove_device(session_token(&headers).unwrap_or_default(), &id) {
        Ok(n) => {
            println!("console: passkey removed ({n} kept)");
            Json(json!({ "ok": true, "kept": n })).into_response()
        }
        Err(e) => error(pair_status(&e), e.message()),
    }
}

/// Starts the passkey approval of one payment; the console shows the intent it approves.
async fn approve_start(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Json(intent): Json<pay::Intent>,
) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, true) {
        return error(status, msg);
    }
    let c = st.console.as_deref().expect("signed in implies a console");
    match c.approve_start(intent.hash()) {
        Ok((ceremony, options)) => {
            Json(json!({ "ceremony": ceremony, "options": options })).into_response()
        }
        Err(e) => error(pair_status(&e), e.message()),
    }
}

/// Grants a one-time approval of that payment after a fresh assertion with user verification.
async fn approve_finish(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, true) {
        return error(status, msg);
    }
    let c = st.console.as_deref().expect("signed in implies a console");
    let (Some(ceremony), Ok(credential)) = (
        body["ceremony"].as_str(),
        serde_json::from_value(body["credential"].clone()),
    ) else {
        return error(StatusCode::BAD_REQUEST, "ceremony or credential is missing");
    };
    match c.approve_finish(ceremony, &credential) {
        Ok(approval) => {
            println!("console: payment approved");
            Json(json!({ "approval": approval, "expires_in": 300 })).into_response()
        }
        Err(e) => error(pair_status(&e), e.message()),
    }
}

async fn mail_list(AxState(st): AxState<State>, headers: HeaderMap) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, false) {
        return error(status, msg);
    }
    match st.mail.list().await {
        Ok((mut messages, refused)) => {
            // Offers are checked here, with the node's keys, not in the console (HNK-26.T5).
            let deals = st.data_dir.join(DEALS_DIR);
            for m in messages.iter_mut() {
                let Some(h) = m["relay_id"].as_str().and_then(|id| st.mail.header(id)) else {
                    continue;
                };
                if h["type"] == "deal.offer" {
                    m["offer"] = offer::summary(&h, &deals);
                }
                // A buyer history from an identity key the financier did not register is flagged.
                if h["type"] == "history.chain" {
                    m["identity"] = st.buyers.flag(&h);
                }
            }
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
    if st.console.as_ref().is_some_and(|c| c.demo) {
        return error(
            StatusCode::FORBIDDEN,
            "this is the demo console: that is turned off here",
        );
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

/// The KYC registry of buyers (HNK-26.T7): read from a signed-in console.
async fn buyers_list(AxState(st): AxState<State>, headers: HeaderMap) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, false) {
        return error(status, msg);
    }
    Json(json!({ "buyers": st.buyers.list() })).into_response()
}

/// Writes to the registry: signed in, from the console's own origin, not in the demo.
fn buyers_writable(st: &State, headers: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    st.signed_in(headers, true)?;
    if st.console.as_ref().is_some_and(|c| c.demo) {
        return Err((
            StatusCode::FORBIDDEN,
            "this is the demo console: that is turned off here",
        ));
    }
    Ok(())
}

fn registry_error(e: buyers::RegistryError) -> Response {
    match e {
        buyers::RegistryError::Input(msg) => error(StatusCode::BAD_REQUEST, msg),
        buyers::RegistryError::Full => error(
            StatusCode::CONFLICT,
            "the registry is full: remove a buyer first",
        ),
        buyers::RegistryError::Io(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the node could not save the registry",
        ),
    }
}

async fn buyers_add(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err((status, msg)) = buyers_writable(&st, &headers) {
        return error(status, msg);
    }
    match st.buyers.add(
        body["identity_pk"].as_str().unwrap_or_default(),
        body["label"].as_str().unwrap_or_default(),
        unix_now(),
    ) {
        Ok(b) => Json(json!({ "ok": true, "buyer": b })).into_response(),
        Err(e) => registry_error(e),
    }
}

async fn buyers_remove(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Path(pk): Path<String>,
) -> Response {
    if let Err((status, msg)) = buyers_writable(&st, &headers) {
        return error(status, msg);
    }
    match st.buyers.remove(&pk) {
        Ok(true) => Json(json!({ "ok": true })).into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "this buyer is not registered"),
        Err(e) => registry_error(e),
    }
}

const DEALS_DIR: &str = "deals";

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The operator accepts an offer from the mailbox with its own advance and confirmations: the
/// node checks the offer again, saves the terms once per invoice, and sends the supplier the
/// commitment opening (HNK-26.T5, SEQ-03 part 1 and 2).
async fn offer_accept(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, true) {
        return error(status, msg);
    }
    if st.console.as_ref().is_some_and(|c| c.demo) {
        return error(
            StatusCode::FORBIDDEN,
            "this is the demo console: that is turned off here",
        );
    }
    let Some(h) = st.mail.header(&id) else {
        return error(
            StatusCode::NOT_FOUND,
            "list the mailbox again; this offer is not in it",
        );
    };
    let o = match offer::read(&h) {
        Ok(o) => o,
        Err(problem) => return error(StatusCode::UNPROCESSABLE_ENTITY, &problem),
    };
    let (Some(advance), Some(confirmations)) = (
        body["advance_zat"].as_u64(),
        body["min_confirmations"]
            .as_u64()
            .and_then(|c| u32::try_from(c).ok()),
    ) else {
        return error(
            StatusCode::BAD_REQUEST,
            "give the advance and the confirmations",
        );
    };
    let now = unix_now();
    let deals = st.data_dir.join(DEALS_DIR);
    let a = match offer::accept(
        &deals,
        &o,
        advance,
        confirmations,
        (now / 86_400) as u32,
        now,
    ) {
        Ok(a) => a,
        Err(offer::AcceptError::Terms(msg)) => return error(StatusCode::BAD_REQUEST, msg),
        Err(offer::AcceptError::Taken) => {
            return error(
                StatusCode::CONFLICT,
                "this invoice was accepted already: one deal per invoice",
            )
        }
        Err(offer::AcceptError::Io(_)) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the node could not save the deal",
            )
        }
    };
    let mailbox_pk = match message::unhex::<32>(&st.public.mailbox_pk) {
        Ok(pk) => pk,
        Err(_) => {
            offer::forget(&deals, &a.n);
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the node has no mailbox key",
            );
        }
    };
    let sent = match offer::opening_message(&st.financier, &mailbox_pk, &a, now) {
        Ok((bytes, to)) => st.mail.send(&to, &bytes).await.map_err(|e| e.to_string()),
        Err(e) => Err(e),
    };
    match sent {
        Ok(_) => Json(json!({ "ok": true, "deal": a })).into_response(),
        Err(e) => {
            // Nothing reached the supplier: forget the terms so the operator can try again.
            offer::forget(&deals, &a.n);
            error(
                StatusCode::BAD_GATEWAY,
                &format!("the reply did not reach the supplier: {e}"),
            )
        }
    }
}

fn pair_status(e: &console::PairError) -> StatusCode {
    use console::PairError::*;
    match e {
        NoCode | Expired | Ceremony | LoginGone => StatusCode::GONE,
        NotPaired => StatusCode::CONFLICT,
        NotApproved => StatusCode::FORBIDDEN,
        Locked => StatusCode::TOO_MANY_REQUESTS,
        OwnDevice => StatusCode::CONFLICT,
        DemoOff => StatusCode::FORBIDDEN,
        NoDevice => StatusCode::NOT_FOUND,
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
            Json(json!({ "ceremony": ceremony, "options": options, "name": st.name() }))
                .into_response()
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
        Ok((n, token)) => {
            println!("console: passkey paired ({n} kept)");
            (
                [(
                    header::SET_COOKIE,
                    session_cookie(&token, console::SESSION_TTL.as_secs()),
                )],
                Json(json!({ "ok": true, "credentials": n, "name": st.name() })),
            )
                .into_response()
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
    // The financier's name only to its own session: /node/console/session is public.
    let name = if open { st.name() } else { None };
    let demo = st.console.as_ref().is_some_and(|c| c.demo);
    Json(json!({ "signed_in": open, "paired": paired, "console": st.console.is_some(), "name": name, "demo": demo }))
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
        .route("/node/console/name", post(set_name))
        .route("/node/console/devices", get(devices_list))
        .route("/node/console/devices/{id}", delete(device_remove))
        .route("/node/console/devices/code", post(device_code))
        .route("/node/console/approve/start", post(approve_start))
        .route("/node/console/approve/finish", post(approve_finish))
        .route("/node/board", get(board_snapshot))
        .route("/node/mail", get(mail_list))
        .route("/node/mail/{id}", delete(mail_remove))
        .route("/node/console/offers/{id}/accept", post(offer_accept))
        .route("/node/console/buyers", get(buyers_list).post(buyers_add))
        .route("/node/console/buyers/{pk}", delete(buyers_remove))
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
    // The provider's commands run on the provider's machine and need no node settings.
    if cmd == "provider" {
        let args: Vec<String> = std::env::args().skip(2).collect();
        if let Err(e) = provider::run(&args).await {
            fail(e);
        }
        return;
    }
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
                console::Console::new(
                    o,
                    &cfg.data_dir,
                    node.keys.console_user(),
                    cfg.setup_code.as_deref(),
                    cfg.demo,
                )
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
                data_dir: cfg.data_dir.clone(),
                name: Arc::new(std::sync::RwLock::new(
                    std::fs::read_to_string(cfg.data_dir.join(NAME_FILE))
                        .ok()
                        .and_then(|n| clean_name(&n))
                        .or_else(|| cfg.financier_name.clone()),
                )),
                public: Arc::new(p),
                console,
                origin: cfg.node_origin.clone(),
                mail: Arc::new(mail::Mail::new(relay, node.keys.mailbox())),
                financier: Arc::new(node.keys.financier()),
                buyers: Arc::new(buyers::Registry::load(&cfg.data_dir).unwrap_or_else(|e| fail(e))),
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

#[cfg(test)]
mod name_tests {
    #[test]
    fn names_are_printable_trimmed_and_short() {
        assert_eq!(
            super::clean_name("  Kurogane Capital \n"),
            Some("Kurogane Capital".into())
        );
        assert_eq!(super::clean_name("a\u{0}b"), Some("ab".into()));
        assert_eq!(super::clean_name("   "), None);
        assert_eq!(super::clean_name(&"x".repeat(80)).unwrap().len(), 60);
    }
}
