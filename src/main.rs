//! jitsuin-node: a financier's node (HNK-26). This first part sets the node up on testnet
//! (HNK-26.T1) and serves its public identity; the deal API, the relay mailbox and the console
//! follow.
//!
//! Runs behind Railway's HTTPS edge, which forwards plain HTTP to PORT inside the container.

mod config;
mod keys;
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
}

fn public(cfg: &config::Config, node: &setup::Node) -> Public {
    let mb = node.keys.mailbox();
    Public {
        network: cfg.network.clone(),
        financier_pk: hex(&node.keys.financier().verifying_key().to_bytes()),
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
        "serve" => {
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
            eprintln!("unknown command {other}: use setup, info or serve");
            std::process::exit(2);
        }
    }
}
