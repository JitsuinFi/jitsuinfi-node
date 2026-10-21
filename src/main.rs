//! jitsuin-node: a financier's node (HNK-26). This first part sets the node up on testnet
//! (HNK-26.T1), serves its public identity, and registers the financier mailbox at the relay
//! (HNK-26.T4); the deal API and the console follow.
//!
//! Runs behind Railway's HTTPS edge, which forwards plain HTTP to PORT inside the container.

mod board;
mod buyers;
mod config;
mod console;
mod deals;
mod directory;
mod fund;
mod keys;
mod mail;
mod mandate;
mod message;
mod offer;
mod pay;
mod provider;
mod relay;
mod reputation;
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
    /// The financier's spending wallet: deposits are checked in it, payouts paid from it.
    wallet: Arc<jitsuin_wallet::Devtool>,
    /// One change of the fund ledger at a time (HNK-30.T23).
    fund: Arc<tokio::sync::Mutex<()>>,
    /// Close plans waiting for their passkey approval, by id.
    plans: Arc<std::sync::Mutex<std::collections::HashMap<String, fund::Plan>>>,
    /// The watch-only board wallet and the server, for the deal flow (HNK-26.T16).
    board_watch: Arc<jitsuin_wallet::Devtool>,
    /// The zcash-devtool binary, for commands the wallet crate does not wrap (new addresses).
    devtool: std::path::PathBuf,
    lightwalletd: String,
    /// The board's address, where the node posts register entries (`BOARD_ADDRESS`, else the
    /// board wallet's default address).
    board_address: Arc<std::sync::RwLock<Option<String>>>,
    /// One deal step at a time.
    deal_lock: Arc<tokio::sync::Mutex<()>>,
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
    Json(body): Json<Value>,
) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, true) {
        return error(status, msg);
    }
    let c = st.console.as_deref().expect("signed in implies a console");
    // a fund close plan (HNK-30.T23) by its id, or one advance
    let intent = match body["plan"].as_str() {
        Some(id) => match st.plans.lock().unwrap().get(id) {
            Some(p) => p.hash(),
            None => return error(StatusCode::NOT_FOUND, "make the close plan again"),
        },
        None => match serde_json::from_value::<pay::Intent>(body) {
            Ok(i) => i.hash(),
            Err(_) => return error(StatusCode::BAD_REQUEST, "name the payment to approve"),
        },
    };
    match c.approve_start(intent) {
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
            // HNK-30.T11: what the mailbox says about each N's buyer, for the private mandate
            let mut buyers: std::collections::HashMap<String, mandate::Buyer> = Default::default();
            for m in &messages {
                let Some(h) = m["relay_id"].as_str().and_then(|id| st.mail.header(id)) else {
                    continue;
                };
                if let (true, Some(n)) = (h["type"] == "history.chain", h["n"].as_str()) {
                    let b = buyers.entry(n.to_string()).or_default();
                    let k = h["body"]["certs"].as_array().map_or(0, |c| c.len() as u32);
                    b.history = Some(b.history.unwrap_or(0).max(k));
                    b.registered |= st.buyers.flag(&h)["registered"] == true;
                }
            }
            let private = mandate::PrivateMandate::load(&st.data_dir);
            let today = (unix_now() / 86_400) as u32;
            for m in messages.iter_mut() {
                let Some(h) = m["relay_id"].as_str().and_then(|id| st.mail.header(id)) else {
                    continue;
                };
                if h["type"] == "deal.offer" {
                    let mut o = offer::summary(&h, &deals);
                    if let Some(sent) = h["sent_at"].as_u64() {
                        o["expires_at"] = (sent.min(unix_now()) + OFFER_TTL_SECS).into();
                    }
                    if o["ok"] == true {
                        let b = o["n"]
                            .as_str()
                            .and_then(|n| buyers.get(n))
                            .cloned()
                            .unwrap_or_default();
                        let mut v = mandate::verdict(&private, &o, &b, today);
                        v["decline_reason"] = mandate::decline_reason(&v).into();
                        o["mandate"] = v;
                    }
                    m["offer"] = o;
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

const MANDATE_FILE: &str = "mandate.json";

/// The financier's public mandate (HNK-30.T19, D-47), as it last sent it to the directory.
async fn mandate_get(AxState(st): AxState<State>, headers: HeaderMap) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, false) {
        return error(status, msg);
    }
    let saved: Value = std::fs::read(st.data_dir.join(MANDATE_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    Json(json!({ "mandate": saved })).into_response()
}

/// Saves the public mandate and sends it, signed with the financier key, to the node provider's
/// mailbox as a `financier.listing`; the provider lists it in the directory (D-47).
async fn mandate_set(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err((status, msg)) = buyers_writable(&st, &headers) {
        return error(status, msg);
    }
    let Some(name) = st.name() else {
        return error(
            StatusCode::BAD_REQUEST,
            "set your name first: suppliers see it in the directory",
        );
    };
    let mandate = match serde_json::from_value::<directory::Mandate>(body.clone()) {
        Ok(m) => m,
        Err(_) => {
            return error(
                StatusCode::BAD_REQUEST,
                "give the amount range, the longest tenor and the KYC rule",
            )
        }
    };
    if let Err(e) = directory::listing(
        &name,
        &st.public.contact,
        &st.public.financier_pk,
        mandate.clone(),
        unix_now(),
    ) {
        return error(StatusCode::BAD_REQUEST, &e);
    }
    let Ok(my_mailbox) = message::unhex::<32>(&st.public.mailbox_pk) else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the node has no mailbox key",
        );
    };
    let bytes = match directory::listing_message(
        &st.financier,
        &my_mailbox,
        &name,
        &st.public.contact,
        &mandate,
        unix_now(),
    ) {
        Ok(b) => b,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    let to = match directory::provider_mailbox() {
        Ok(t) => t,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    if let Err(e) = st.mail.send(&to, &bytes).await {
        return error(
            StatusCode::BAD_GATEWAY,
            &format!("the listing did not reach the provider: {e}"),
        );
    }
    if std::fs::write(
        st.data_dir.join(MANDATE_FILE),
        serde_json::to_vec(&mandate).unwrap(),
    )
    .is_err()
    {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "sent, but the node could not save the mandate",
        );
    }
    Json(json!({ "ok": true, "mandate": mandate })).into_response()
}

/// Asks the provider to attest this financier's record (HNK-30.T21, D-48): the node sends the
/// `(N, salt)` of every deal it accepted, sealed and signed with the financier key.
async fn reputation_request(AxState(st): AxState<State>, headers: HeaderMap) -> Response {
    if let Err((status, msg)) = buyers_writable(&st, &headers) {
        return error(status, msg);
    }
    let ns: Vec<[u8; 32]> = std::fs::read_dir(st.data_dir.join(DEALS_DIR))
        .map(|d| {
            d.filter_map(|e| {
                e.ok()?
                    .file_name()
                    .to_str()?
                    .strip_suffix(".json")
                    .map(String::from)
            })
            .filter_map(|n| message::unhex::<32>(&n).ok())
            .collect()
        })
        .unwrap_or_default();
    if ns.is_empty() {
        return error(
            StatusCode::CONFLICT,
            "no deals yet: a record starts with the first accepted offer",
        );
    }
    let (Ok(me), Ok(to)) = (
        message::unhex::<32>(&st.public.mailbox_pk),
        directory::provider_mailbox(),
    ) else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the node has no mailbox key",
        );
    };
    let bytes = match reputation::request_message(&st.financier, &me, &to, &ns, unix_now()) {
        Ok(b) => b,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    match st.mail.send(&to, &bytes).await {
        Ok(_) => Json(json!({ "ok": true, "deals": ns.len() })).into_response(),
        Err(e) => error(
            StatusCode::BAD_GATEWAY,
            &format!("the request did not reach the provider: {e}"),
        ),
    }
}

fn fund_error(e: impl std::fmt::Display) -> Response {
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        &format!("the fund ledger could not be read or saved: {e}"),
    )
}

/// The wallet's transactions and balance, after a sync (zcash-devtool blocks: off the runtime).
async fn wallet_state(st: &State) -> Result<(Vec<jitsuin_wallet::WalletTx>, u64), String> {
    let (w, b) = (st.wallet.clone(), st.board.clone());
    tokio::task::spawn_blocking(move || {
        let _g = b.chain.lock().unwrap_or_else(|p| p.into_inner());
        w.sync()?;
        w.enhance()?;
        Ok::<_, jitsuin_wallet::Error>((w.list_tx()?, w.balance_zat()?))
    })
    .await
    .expect("wallet task")
    .map_err(|e| format!("the wallet could not sync: {e}"))
}

async fn send_fund(st: &State, kind: &str, to: &[u8; 32], body: Value) -> Result<(), String> {
    let me = message::unhex::<32>(&st.public.mailbox_pk)?;
    let bytes = fund::message(kind, &st.financier, &me, to, body, unix_now())?;
    st.mail
        .send(to, &bytes)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// The fund at a glance for its manager: period, price, units, the queue, past closes.
async fn fund_get(AxState(st): AxState<State>, headers: HeaderMap) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, false) {
        return error(status, msg);
    }
    let l = match fund::Ledger::load(&st.data_dir) {
        Ok(l) => l,
        Err(e) => return fund_error(e),
    };
    Json(json!({
        "period": l.period,
        "nav": l.nav,
        "total_units": l.total_units(),
        "leaves": l.leaves.len(),
        "deposits": l.deposits.len(),
        "queue": l.queue,
        "closes": l.closes.iter().rev().take(12).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// Records a deposit the wallet received (mined) for a member, and sends the member a receipt
/// with the withdraw token of the new units.
async fn fund_deposit(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err((status, msg)) = buyers_writable(&st, &headers) {
        return error(status, msg);
    }
    let (Some(member), Some(txid)) = (
        body["member"].as_str().and_then(fund::member_mailbox),
        body["txid"].as_str().map(str::trim),
    ) else {
        return error(
            StatusCode::BAD_REQUEST,
            "give the member's contact card and the deposit's transaction id",
        );
    };
    let (txs, _) = match wallet_state(&st).await {
        Ok(w) => w,
        Err(msg) => return error(StatusCode::BAD_GATEWAY, &msg),
    };
    let Some(amount) = fund::received(&txs, txid).filter(|a| *a > 0) else {
        return error(
            StatusCode::NOT_FOUND,
            "the wallet has no mined deposit with that transaction id yet",
        );
    };
    let _g = st.fund.lock().await;
    let mut l = match fund::Ledger::load(&st.data_dir) {
        Ok(l) => l,
        Err(e) => return fund_error(e),
    };
    let mut token = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut token);
    let units = match l.deposit(&member, amount, txid, &token) {
        Ok(u) => u,
        Err(msg) => return error(StatusCode::CONFLICT, &msg),
    };
    if let Err(e) = l.save(&st.data_dir) {
        return fund_error(e);
    }
    let receipt = json!({
        "period": l.period,
        "deposit_txid": txid,
        "amount_zat": amount,
        "units": units,
        "nav": l.nav,
        "withdraw_token": hex(&token),
    });
    let sent = send_fund(&st, "fund.receipt", &member, receipt).await;
    Json(json!({ "ok": true, "amount_zat": amount, "units": units, "receipt_sent": sent.is_ok() }))
        .into_response()
}

/// Queues a member's `fund.withdraw` from the mailbox for the end of the period.
async fn fund_queue(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err((status, msg)) = buyers_writable(&st, &headers) {
        return error(status, msg);
    }
    let Some(h) = st.mail.header(&id) else {
        return error(
            StatusCode::NOT_FOUND,
            "list the mailbox again; this request is not in it",
        );
    };
    let w = match fund::read_withdraw(&h) {
        Ok(r) => r,
        Err(msg) => return error(StatusCode::UNPROCESSABLE_ENTITY, &msg),
    };
    let _g = st.fund.lock().await;
    let mut l = match fund::Ledger::load(&st.data_dir) {
        Ok(l) => l,
        Err(e) => return fund_error(e),
    };
    match l.withdraw(&w.token, w.units, &w.address, &id, unix_now()) {
        Ok(u) => match l.save(&st.data_dir) {
            Ok(()) => Json(json!({ "ok": true, "units": u, "period": l.period })).into_response(),
            Err(e) => fund_error(e),
        },
        Err(msg) => error(StatusCode::CONFLICT, &msg),
    }
}

/// Values the fund from the wallet and plans the close: the payouts the passkey will approve.
async fn fund_plan(AxState(st): AxState<State>, headers: HeaderMap) -> Response {
    if let Err((status, msg)) = buyers_writable(&st, &headers) {
        return error(status, msg);
    }
    let (txs, cash) = match wallet_state(&st).await {
        Ok(w) => w,
        Err(msg) => return error(StatusCode::BAD_GATEWAY, &msg),
    };
    let manager = st.financier.verifying_key().to_bytes();
    let view = jitsuin_flow::fund::fund_view(
        &txs,
        cash,
        &manager,
        (unix_now() / 86_400) as u32,
        GRACE_DAYS,
    );
    let _g = st.fund.lock().await;
    let l = match fund::Ledger::load(&st.data_dir) {
        Ok(l) => l,
        Err(e) => return fund_error(e),
    };
    let plan = l.plan(fund::assets(&view), view.cash_zat);
    let id = message::random_id();
    let out = json!({ "plan_id": id, "plan": plan, "paid_zat": plan.paid_zat() });
    st.plans.lock().unwrap().insert(id, plan);
    Json(out).into_response()
}

/// Days after the due date before an unpaid receivable counts as overdue.
const GRACE_DAYS: u32 = 7;

/// Runs an approved close: pays the queue, records it, signs the new root into JTLR, and sends
/// every member their path and every paid member their payout receipt.
async fn fund_close(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err((status, msg)) = buyers_writable(&st, &headers) {
        return error(status, msg);
    }
    let c = st.console.as_deref().expect("signed in implies a console");
    let (Some(id), Some(approval)) = (body["plan_id"].as_str(), body["approval"].as_str()) else {
        return error(StatusCode::BAD_REQUEST, "give the plan and its approval");
    };
    let Some(plan) = st.plans.lock().unwrap().get(id).cloned() else {
        return error(StatusCode::NOT_FOUND, "make the close plan again");
    };
    if let Err(e) = c.take_approval(approval, &plan.hash()) {
        return error(pair_status(&e), e.message());
    }
    let _g = st.fund.lock().await;
    let mut l = match fund::Ledger::load(&st.data_dir) {
        Ok(l) => l,
        Err(e) => return fund_error(e),
    };
    if l.digest() != plan.ledger {
        return error(
            StatusCode::CONFLICT,
            "the fund changed since this plan: make the plan again",
        );
    }
    st.plans.lock().unwrap().remove(id);
    // 1. the payouts, one transaction
    let payout_txid = if plan.payouts.is_empty() {
        None
    } else {
        let w = st.wallet.clone();
        let payments: Vec<_> = plan
            .payouts
            .iter()
            .map(|p| jitsuin_wallet::Payment {
                address: p.address.clone(),
                amount_zat: p.amount_zat,
                memo: None,
            })
            .collect();
        let b = st.board.clone();
        match tokio::task::spawn_blocking(move || {
            let _g = b.chain.lock().unwrap_or_else(|p| p.into_inner());
            w.pay(&payments)
        })
        .await
        .expect("wallet task")
        {
            Ok(t) => Some(t),
            Err(e) => {
                return error(
                    StatusCode::BAD_GATEWAY,
                    &format!("the payouts were not sent: {e}"),
                )
            }
        }
    };
    // 2. the ledger, saved before anything else can fail: the money has left
    let paid = match l.apply(&plan, || {
        let mut t = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut t);
        t
    }) {
        Ok(p) => p,
        Err(msg) => return error(StatusCode::CONFLICT, &msg),
    };
    let tree = l.tree();
    let (root, total) = tree.root();
    l.closes.push(fund::Close {
        period: plan.period,
        root: hex(&root),
        total_units: total,
        nav: plan.nav,
        paid_zat: plan.paid_zat(),
        payout_txid: payout_txid.clone(),
        root_txid: String::new(),
        held: plan.held,
    });
    if let Err(e) = l.save(&st.data_dir) {
        return fund_error(e);
    }
    // 3. the root, signed by the manager key, as a self-send members see with the viewing key
    let key = st.financier.clone();
    let w = st.wallet.clone();
    let period = plan.period;
    let b = st.board.clone();
    let root_txid = tokio::task::spawn_blocking(move || {
        let _g = b.chain.lock().unwrap_or_else(|p| p.into_inner());
        let r = jitsuin_core::LiabilityRoot::sign(&key, period, root, total);
        let memo = jitsuin_core::memo::encode(&[jitsuin_core::MemoItem::Root(r)])
            .map_err(|e| e.to_string())?;
        let own = w.default_address().map_err(|e| e.to_string())?;
        w.pay(&[jitsuin_wallet::Payment {
            address: own,
            amount_zat: jitsuin_flow::fund::ROOT_POST_ZAT,
            memo: Some(jitsuin_wallet::PaymentMemo::Arbitrary(memo)),
        }])
        .map_err(|e| e.to_string())
    })
    .await
    .expect("wallet task");
    if let Ok(t) = &root_txid {
        if let Some(last) = l.closes.last_mut() {
            last.root_txid = t.clone();
        }
        if let Err(e) = l.save(&st.data_dir) {
            return fund_error(e);
        }
    }
    // 4. the mail: paths to every member, payout receipts to the paid ones
    let mut undelivered = 0;
    for p in &paid {
        let Ok(to) = message::unhex::<32>(&p.mailbox_pk) else {
            continue;
        };
        let mut body = json!({
            "period": plan.period,
            "leaf_id": p.payout.leaf,
            "units": p.payout.units,
            "amount_zat": p.payout.amount_zat,
            "nav": plan.nav,
            "txid": payout_txid,
        });
        if let Some((t, _)) = &p.next {
            body["next_token"] = hex(t).into();
        }
        if send_fund(&st, "fund.payout", &to, body).await.is_err() {
            undelivered += 1;
        }
    }
    for leaf in &l.leaves {
        let (Ok(to), Some(body)) = (
            message::unhex::<32>(&leaf.mailbox_pk),
            fund::path_body(&tree, leaf, plan.period),
        ) else {
            continue;
        };
        if send_fund(&st, "fund.merkle_path", &to, body).await.is_err() {
            undelivered += 1;
        }
    }
    Json(json!({
        "ok": true,
        "period": plan.period,
        "paid_zat": plan.paid_zat(),
        "payout_txid": payout_txid,
        "root": hex(&root),
        "total_units": total,
        "root_txid": root_txid.as_ref().ok(),
        "root_error": root_txid.err(),
        "undelivered": undelivered,
    }))
    .into_response()
}

/// The private mandate (HNK-30.T11): kept on this node only, never sent anywhere.
async fn private_get(AxState(st): AxState<State>, headers: HeaderMap) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, false) {
        return error(status, msg);
    }
    Json(json!({ "mandate": mandate::PrivateMandate::load(&st.data_dir) })).into_response()
}

async fn private_set(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err((status, msg)) = buyers_writable(&st, &headers) {
        return error(status, msg);
    }
    let m = match serde_json::from_value::<mandate::PrivateMandate>(body) {
        Ok(m) => m,
        Err(_) => return error(StatusCode::BAD_REQUEST, "these are not mandate rules"),
    };
    if let Err(msg) = m.check() {
        return error(StatusCode::BAD_REQUEST, msg);
    }
    match m.save(&st.data_dir) {
        Ok(()) => Json(json!({ "ok": true, "mandate": m })).into_response(),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the node could not save the mandate",
        ),
    }
}

/// Declines an offer (HNK-26.T6): a signed `deal.decline` to the supplier, naming only which kind
/// of rule it breaks, then the offer leaves the mailbox. An accepted offer cannot be declined.
async fn offer_decline(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    if let Err((status, msg)) = buyers_writable(&st, &headers) {
        return error(status, msg);
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
    if offer::load(&st.data_dir.join(DEALS_DIR), &o.n).is_some() {
        return error(
            StatusCode::CONFLICT,
            "this offer was accepted: it cannot be declined",
        );
    }
    let reason: String = body["reason"]
        .as_str()
        .unwrap_or("The financier declined this offer.")
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    let reason = match reason.trim() {
        "" => "The financier declined this offer.".to_string(),
        r => r.to_string(),
    };
    if let Err(e) = send_decline(&st, &id, &h, &o.n, &reason).await {
        return error(StatusCode::BAD_GATEWAY, &e);
    }
    Json(json!({ "ok": true, "reason": reason })).into_response()
}

/// Sends a signed `deal.decline` for the offer `id` (header `h`, invoice `n`) and removes it.
async fn send_decline(
    st: &State,
    id: &str,
    h: &Value,
    n: &str,
    reason: &str,
) -> Result<(), String> {
    let me = message::unhex::<32>(&st.public.mailbox_pk)?;
    let to = h["from"]["mailbox_pk"]
        .as_str()
        .ok_or("the offer has no reply mailbox")
        .and_then(|p| message::unhex::<32>(p).map_err(|_| "the offer has no reply mailbox"))?;
    let mut d = message::draft(
        "deal.decline",
        &me,
        &to,
        Some(n),
        json!({ "reason": reason }),
        &[],
        unix_now(),
    );
    message::sign(&mut d, &st.financier);
    let bytes = message::encode(&d, &[])?;
    st.mail
        .send(&to, &bytes)
        .await
        .map_err(|e| format!("the decline did not reach the supplier: {e}"))?;
    let _ = st.mail.remove(id).await;
    Ok(())
}

/// Offers left unanswered this long expire (HNK-26.T6): the supplier hears so and may go to
/// another financier.
const OFFER_TTL_SECS: u64 = 7 * 86_400;

/// Declines every offer older than `OFFER_TTL_SECS` that was not accepted.
async fn expire_offers(st: &State) {
    let Ok((list, _)) = st.mail.list().await else {
        return;
    };
    let deals = st.data_dir.join(DEALS_DIR);
    let now = unix_now();
    for m in list {
        let Some(id) = m["relay_id"].as_str() else {
            continue;
        };
        let Some(h) = st.mail.header(id) else {
            continue;
        };
        if h["type"] != "deal.offer" {
            continue;
        }
        let sent = h["sent_at"].as_u64().unwrap_or(now).min(now);
        let Ok(o) = offer::read(&h) else { continue };
        if now - sent < OFFER_TTL_SECS || offer::load(&deals, &o.n).is_some() {
            continue;
        }
        let r = "This offer expired: the financier did not answer within 7 days.";
        if let Err(e) = send_decline(st, id, &h, &o.n, r).await {
            eprintln!("offer {}…: {e}", &o.n[..8]);
        }
    }
}

/// The financier as `jitsuin_flow` needs it: wallets, board address, server, key.
async fn financier(st: &State) -> Result<jitsuin_flow::financier::Financier, String> {
    let known = st.board_address.read().unwrap().clone();
    let board_address = match known {
        Some(a) => a,
        None => {
            let (w, b) = (st.board_watch.clone(), st.board.clone());
            let a = tokio::task::spawn_blocking(move || {
                let _g = b.chain.lock().unwrap_or_else(|p| p.into_inner());
                w.default_address()
            })
            .await
            .expect("wallet task")
            .map_err(|e| format!("the board address is not known: {e}"))?;
            *st.board_address.write().unwrap() = Some(a.clone());
            a
        }
    };
    Ok(jitsuin_flow::financier::Financier {
        wallet: (*st.wallet).clone(),
        board_watch: (*st.board_watch).clone(),
        board_address,
        lightwalletd: st.lightwalletd.clone(),
        key: (*st.financier).clone(),
    })
}

/// Messages in the mailbox for deal `n` of type `kind`: (relay id, header).
async fn mail_for(st: &State, n: &str, kind: &str) -> Vec<(String, Value)> {
    let Ok((list, _)) = st.mail.list().await else {
        return vec![];
    };
    list.iter()
        .filter_map(|m| {
            let id = m["relay_id"].as_str()?;
            let h = st.mail.header(id)?;
            (h["type"] == kind && h["n"].as_str() == Some(n)).then(|| (id.to_string(), h))
        })
        .collect()
}

/// Moves deal `n` as far as it can go without the operator: board checks from the latest scan,
/// the supplier's entry, posting it, the letter, the seals, the advance's confirmation. Returns
/// the deal's view. Paying the advance is not here: it needs a passkey (`deal_pay`).
async fn drive(st: &State, n: &str) -> Result<Value, String> {
    use jitsuin_flow::financier::{Event, State as S};
    let _g = st.deal_lock.lock().await;
    let dir = st.data_dir.join(DEALS_DIR);
    let mut flow = deals::load_flow(&dir, n).ok_or("no deal with this N")?;
    let mut meta = deals::load_meta(&dir, n);
    let me = message::unhex::<32>(&st.public.mailbox_pk)?;
    let accepted = offer::load(&dir, n).ok_or("the deal's terms are gone")?;
    meta.problem = None;
    for _ in 0..6 {
        let before = flow.state().name();
        let step: Result<(), String> = async {
            match flow.state().clone() {
                S::Check | S::AwaitConfirmation { .. } => {
                    let (records, tip) = st
                        .board
                        .records()
                        .ok_or("waiting for the first board scan")?;
                    let lookup = jitsuin_board::lookup(
                        &records,
                        flow.nullifier(),
                        &flow.deal().invoice.supplier_ephemeral_pk,
                    );
                    flow.apply(Event::BoardChecked {
                        lookup,
                        tip_height: tip,
                    })
                    .map_err(|e| e.to_string())?;
                }
                S::AwaitSupplierSignature => {
                    for (_, h) in mail_for(st, n, "deal.entry").await {
                        let Ok(entry) = deals::read_entry(&h, n) else {
                            continue;
                        };
                        if flow.apply(Event::SupplierSigned(entry)).is_ok() {
                            break;
                        }
                    }
                }
                S::Register { .. } => {
                    let fin = financier(st).await?;
                    let b = st.board.clone();
                    let mut f = flow.clone();
                    flow = tokio::task::spawn_blocking(move || {
                        let _g = b.chain.lock().unwrap_or_else(|p| p.into_inner());
                        fin.register(&mut f)?;
                        Ok::<_, jitsuin_flow::Error>(f)
                    })
                    .await
                    .expect("wallet task")
                    .map_err(|e| format!("posting the entry failed: {e}"))?;
                }
                S::AwaitAssignment { .. } => {
                    if !meta.letter_sent {
                        let pdf =
                            std::fs::read(deals::pdf_path(&dir, n)).map_err(|e| e.to_string())?;
                        let mut to = vec![message::unhex::<32>(&accepted.supplier_mailbox_pk)?];
                        if let Some(b) = &accepted.buyer_mailbox_pk {
                            to.push(message::unhex::<32>(b)?);
                        }
                        for t in to {
                            let bytes = deals::letter_message(
                                &st.financier,
                                &me,
                                &t,
                                &flow,
                                &pdf,
                                unix_now(),
                            )?;
                            st.mail
                                .send(&t, &bytes)
                                .await
                                .map_err(|e| format!("the letter did not go out: {e}"))?;
                        }
                        meta.letter_sent = true;
                    }
                    let mut seals: [Option<jitsuin_core::Seal>; 2] = [None, None];
                    for (_, h) in mail_for(st, n, "deal.seal").await {
                        if let Ok((i @ 0..=1, s)) = deals::read_seal(&h, n) {
                            seals[i as usize] = Some(s);
                        }
                    }
                    if let [Some(s0), Some(s1)] = seals {
                        meta.seals = [&s0, &s1]
                            .iter()
                            .map(|s| {
                                base64::Engine::encode(
                                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                                    s.to_bytes(),
                                )
                            })
                            .collect();
                        flow.apply(Event::AssignmentSealed(vec![s0, s1]))
                            .map_err(|e| format!("the seals do not hold: {e}"))?;
                    }
                }
                S::AwaitAdvanceConfirmation { advance_txid, .. } => {
                    let (w, b, l) = (st.wallet.clone(), st.board.clone(), st.lightwalletd.clone());
                    let txid = advance_txid.clone();
                    let (mined, tip) = tokio::task::spawn_blocking(move || {
                        let _g = b.chain.lock().unwrap_or_else(|p| p.into_inner());
                        w.sync().map_err(|e| e.to_string())?;
                        let mined = w
                            .list_tx()
                            .map_err(|e| e.to_string())?
                            .iter()
                            .any(|t| t.txid == txid && t.mined_height.is_some());
                        let tip =
                            jitsuin_board::lwd::latest_height(&l).map_err(|e| e.to_string())?;
                        Ok::<_, String>((mined, tip))
                    })
                    .await
                    .expect("wallet task")?;
                    flow.apply(Event::AdvanceChecked {
                        mined,
                        tip_height: tip,
                    })
                    .map_err(|e| e.to_string())?;
                }
                // HNK-26.T11–T12: the buyer pays this wallet at maturity; once mined payments
                // with the buyer's receipt and claim cover the amount, the node countersigns the
                // claim into a `settled` entry on the board, once.
                S::Done { .. } if meta.settled_txid.is_none() => {
                    let fin = financier(st).await?;
                    let b = st.board.clone();
                    let doc = jitsuin_core::SettlementDoc::for_assignment(&flow.deal().assignment);
                    let buyer = flow.deal().invoice.buyer_pk;
                    let today = (unix_now() / 86_400) as u32;
                    let (status, paid, posted) = tokio::task::spawn_blocking(move || {
                        let _g = b.chain.lock().unwrap_or_else(|p| p.into_inner());
                        let r = fin.repayment(&doc, &buyer).map_err(|e| e.to_string())?;
                        let status = r.status(&doc, today, GRACE_DAYS);
                        let posted = if status == jitsuin_flow::settlement::Status::Settled {
                            Some(
                                fin.post_settled(&doc, &buyer, &r)
                                    .map_err(|e| format!("posting the settled entry failed: {e}"))?
                                    .0,
                            )
                        } else {
                            None
                        };
                        Ok::<_, String>((format!("{status:?}"), r.paid_zat, posted))
                    })
                    .await
                    .expect("wallet task")?;
                    meta.repayment = Some(status);
                    meta.paid_zat = Some(paid);
                    meta.settled_txid = posted;
                }
                // HNK-26.T18: once settled, the bundle goes to the supplier and the buyer
                S::Done { .. } if !meta.bundle_sent && meta.seals.len() == 2 => {
                    let bytes = deals::bundle(
                        &flow,
                        &accepted.buyer_signature,
                        &meta.seals,
                        &st.financier,
                    )?;
                    let mut to = vec![message::unhex::<32>(&accepted.supplier_mailbox_pk)?];
                    if let Some(b) = &accepted.buyer_mailbox_pk {
                        to.push(message::unhex::<32>(b)?);
                    }
                    for t in to {
                        let m =
                            deals::bundle_message(&st.financier, &me, &t, n, &bytes, unix_now())?;
                        st.mail
                            .send(&t, &m)
                            .await
                            .map_err(|e| format!("the bundle did not go out: {e}"))?;
                    }
                    meta.bundle_sent = true;
                }
                S::Pay { .. } | S::Done { .. } | S::Stopped(_) => {}
            }
            Ok(())
        }
        .await;
        if let Err(e) = step {
            meta.problem = Some(e);
            break;
        }
        if flow.state().name() == before {
            break;
        }
    }
    deals::save_flow(&dir, n, &flow)?;
    let _ = deals::save_meta(&dir, n, &meta);
    Ok(deal_view(&flow, &meta))
}

fn deal_view(flow: &jitsuin_flow::financier::Flow, meta: &deals::Meta) -> Value {
    let mut v = deals::view(flow);
    v["n"] = hex(flow.nullifier()).into();
    v["invoice_id"] = flow.deal().invoice.invoice_id.clone().into();
    v["amount_zat"] = flow.deal().invoice.amount_zat.into();
    v["advance_zat"] = flow.deal().advance_zat.into();
    v["due_date"] = flow.deal().invoice.due_date.into();
    v["letter_sent"] = meta.letter_sent.into();
    v["repayment"] = meta.repayment.clone().into();
    v["paid_zat"] = meta.paid_zat.into();
    v["settled_txid"] = meta.settled_txid.clone().into();
    v["bundle_sent"] = meta.bundle_sent.into();
    v["problem"] = meta.problem.clone().into();
    if matches!(flow.state(), jitsuin_flow::financier::State::Pay { .. }) {
        let i = pay::Intent::of(flow);
        v["intent"] = json!({ "n": i.n, "amount_zat": i.amount_zat, "address": i.address });
    }
    v
}

/// Every deal moves on its own every two minutes (the board is rescanned as often).
async fn drive_all(st: State) {
    loop {
        tokio::time::sleep(board::EVERY).await;
        if st.console.as_ref().is_some_and(|c| !c.demo) {
            expire_offers(&st).await;
        }
        let dir = st.data_dir.join(DEALS_DIR);
        for n in deals::list(&dir) {
            if let Err(e) = drive(&st, &n).await {
                eprintln!("deal {}…: {e}", &n[..8]);
            }
        }
    }
}

/// The deal pipeline (HNK-26.T16): each deal, its state and what it waits for.
async fn deals_list(AxState(st): AxState<State>, headers: HeaderMap) -> Response {
    if let Err((status, msg)) = st.signed_in(&headers, false) {
        return error(status, msg);
    }
    let dir = st.data_dir.join(DEALS_DIR);
    let mut out: Vec<Value> = deals::list(&dir)
        .iter()
        .filter_map(|n| {
            Some(deal_view(
                &deals::load_flow(&dir, n)?,
                &deals::load_meta(&dir, n),
            ))
        })
        .collect();
    out.reverse();
    Json(json!({ "deals": out })).into_response()
}

/// Moves one deal on now, instead of waiting for the next round.
async fn deal_step(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Path(n): Path<String>,
) -> Response {
    if let Err((status, msg)) = buyers_writable(&st, &headers) {
        return error(status, msg);
    }
    match drive(&st, &n).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => error(StatusCode::NOT_FOUND, &e),
    }
}

/// Pays the advance of a sealed deal with the operator's passkey approval of exactly it (D-43,
/// `pay::advance`), then sends the supplier the txid.
async fn deal_pay(
    AxState(st): AxState<State>,
    headers: HeaderMap,
    Path(n): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    if let Err((status, msg)) = buyers_writable(&st, &headers) {
        return error(status, msg);
    }
    let Some(approval) = body["approval"].as_str().map(String::from) else {
        return error(
            StatusCode::BAD_REQUEST,
            "approve the payment with your passkey first",
        );
    };
    let _g = st.deal_lock.lock().await;
    let dir = st.data_dir.join(DEALS_DIR);
    let Some(mut flow) = deals::load_flow(&dir, &n) else {
        return error(StatusCode::NOT_FOUND, "no deal with this N");
    };
    let fin = match financier(&st).await {
        Ok(f) => f,
        Err(e) => return error(StatusCode::BAD_GATEWAY, &e),
    };
    let console = st.console.clone().expect("signed in implies a console");
    let b = st.board.clone();
    let date = (unix_now() / 86_400) as u32;
    let paid = tokio::task::spawn_blocking(move || {
        let _g = b.chain.lock().unwrap_or_else(|p| p.into_inner());
        let r = pay::advance(&console, &approval, &fin, &mut flow, date).map(|_| ());
        (r, flow)
    })
    .await
    .expect("wallet task");
    let (result, flow) = paid;
    if let Err(e) = deals::save_flow(&dir, &n, &flow) {
        return error(StatusCode::INTERNAL_SERVER_ERROR, &e);
    }
    if let Err(e) = result {
        return error(StatusCode::BAD_GATEWAY, &e.to_string());
    }
    let mut meta = deals::load_meta(&dir, &n);
    let txid = deals::view(&flow)["advance_txid"]
        .as_str()
        .map(String::from);
    if let (Some(txid), Some(a)) = (txid, offer::load(&dir, &n)) {
        if let (Ok(me), Ok(to)) = (
            message::unhex::<32>(&st.public.mailbox_pk),
            message::unhex::<32>(&a.supplier_mailbox_pk),
        ) {
            if let Ok(bytes) =
                deals::advance_message(&st.financier, &me, &to, &flow, &txid, unix_now())
            {
                meta.advance_sent = st.mail.send(&to, &bytes).await.is_ok();
            }
            // HNK-25.T4: the financier's seal completes the letter; the buyer pays only then
            if let Ok(s2) = deals::financier_seal(&flow, &meta.seals, &st.financier) {
                let buyer = a
                    .buyer_mailbox_pk
                    .as_deref()
                    .and_then(|b| message::unhex::<32>(b).ok());
                for t in [Some(to), buyer].into_iter().flatten() {
                    if let Ok(m) = deals::seal_message(&me, &t, &n, &s2, unix_now()) {
                        let _ = st.mail.send(&t, &m).await;
                    }
                }
            }
        }
    }
    let _ = deals::save_meta(&dir, &n, &meta);
    println!("console: advance paid");
    Json(deal_view(&flow, &meta)).into_response()
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
        Ok(_) => {
            // HNK-26.T16: the deal's flow and its letter start now; the driver moves it on.
            // HNK-26.T17: the letter names a fresh address of this wallet for this deal only
            let (bin, dir, b) = (
                st.devtool.clone(),
                st.wallet.wallet_dir().to_path_buf(),
                st.board.clone(),
            );
            let address = tokio::task::spawn_blocking(move || {
                let _g = b.chain.lock().unwrap_or_else(|p| p.into_inner());
                deals::new_address(&bin, &dir)
            })
            .await
            .expect("wallet task")
            .unwrap_or_else(|e| {
                eprintln!("deal: {e}; the letter names the wallet's default address");
                st.public.wallet_address.clone()
            });
            let started = deals::start(
                &deals,
                &a,
                &st.financier,
                &address,
                &st.name().unwrap_or_default(),
            );
            let st2 = st.clone();
            let n = a.n.clone();
            tokio::spawn(async move {
                let _ = drive(&st2, &n).await;
            });
            Json(json!({ "ok": true, "deal": a, "flow": started.err() })).into_response()
        }
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
        .route("/node/console/offers/{id}/decline", post(offer_decline))
        .route("/node/console/deals", get(deals_list))
        .route("/node/console/deals/{n}/step", post(deal_step))
        .route("/node/console/deals/{n}/pay", post(deal_pay))
        .route(
            "/node/console/mandate/private",
            get(private_get).post(private_set),
        )
        .route("/node/console/buyers", get(buyers_list).post(buyers_add))
        .route("/node/console/mandate", get(mandate_get).post(mandate_set))
        .route("/node/console/reputation", post(reputation_request))
        .route("/node/console/fund", get(fund_get))
        .route("/node/console/fund/deposits", post(fund_deposit))
        .route("/node/console/fund/withdrawals/{id}", post(fund_queue))
        .route("/node/console/fund/plan", post(fund_plan))
        .route("/node/console/fund/close", post(fund_close))
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
                wallet: Arc::new(node.wallet.clone()),
                fund: Arc::default(),
                plans: Arc::default(),
                board_watch: Arc::new(node.board_watch.clone()),
                devtool: cfg.devtool.clone(),
                lightwalletd: cfg.lightwalletd.clone(),
                board_address: Arc::new(std::sync::RwLock::new(
                    std::env::var("BOARD_ADDRESS")
                        .ok()
                        .filter(|a| !a.is_empty()),
                )),
                deal_lock: Arc::default(),
            };
            tokio::spawn(drive_all(st.clone()));
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
