//! jitsuin-node: a financier's node (HNK-26). This first part sets the node up on testnet
//! (HNK-26.T1), serves its public identity, and registers the financier mailbox at the relay
//! (HNK-26.T4); the deal API and the console follow.
//!
//! Runs behind Railway's HTTPS edge, which forwards plain HTTP to PORT inside the container.

mod config;
mod keys;
mod message;
mod relay;
mod setup;

use std::sync::Arc;

use axum::http::{header, HeaderValue};
use axum::routing::get;
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

fn app(p: Arc<Public>) -> Router {
    let info = {
        let p = p.clone();
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
            axum::serve(listener, app(Arc::new(p)))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
                .expect("serve");
        }
        other => {
            eprintln!("unknown command {other}: use setup, info, inbox or serve");
            std::process::exit(2);
        }
    }
}
