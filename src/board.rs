//! Live board for the web app (HNK-30.T4, HNK-28.T1, W-23): the node rescans the shielded board
//! with its watch-only wallet of the public board UFVK and serves the entries as the same
//! snapshot JSON that `jitsuin verify --save-board` writes. Anyone can read the board with the
//! published UFVK, so this endpoint reveals nothing new; it saves the browser a Zcash client.

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jitsuin_board::Position;
use jitsuin_wallet::Devtool;
use serde_json::{json, Value};

/// How often the board is rescanned.
pub const EVERY: Duration = Duration::from_secs(120);

#[derive(Default)]
pub struct Board {
    latest: RwLock<Option<Value>>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One scan: entries (register and settled) in board order, as snapshot items.
fn scan_once(watch: &Devtool, lightwalletd: &str) -> Result<Value, String> {
    let report = jitsuin_board::scan(watch, lightwalletd).map_err(|e| e.to_string())?;
    let tip = jitsuin_board::lwd::latest_height(lightwalletd).map_err(|e| e.to_string())?;
    let item = |txid: &str, p: Position, memo: &[u8]| {
        (
            p,
            json!({ "txid": txid, "height": p.height, "tx_index": p.tx_index, "output_index": p.output_index, "memo": URL_SAFE_NO_PAD.encode(memo) }),
        )
    };
    let mut items: Vec<(Position, Value)> = report
        .records
        .iter()
        .map(|r| item(&r.txid, r.position, &r.entry.to_memo_bytes()))
        .chain(
            report
                .settled
                .iter()
                .map(|s| item(&s.txid, s.position, &s.entry.to_memo_bytes())),
        )
        .collect();
    items.sort_by_key(|(p, _)| *p);
    Ok(json!({
        "scanned_at": now(),
        "tip": tip,
        "pending": report.pending,
        "entries": items.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
    }))
}

impl Board {
    pub fn latest(&self) -> Option<Value> {
        self.latest.read().unwrap().clone()
    }

    /// Rescans forever; a failed scan keeps the last good one.
    pub async fn run(self: Arc<Self>, watch: Devtool, lightwalletd: String) {
        loop {
            let (w, l) = (watch.clone(), lightwalletd.clone());
            match tokio::task::spawn_blocking(move || scan_once(&w, &l)).await {
                Ok(Ok(v)) => {
                    println!(
                        "board: {} entries up to block {}",
                        v["entries"].as_array().map_or(0, |a| a.len()),
                        v["tip"]
                    );
                    *self.latest.write().unwrap() = Some(v);
                }
                Ok(Err(e)) => eprintln!("board: scan failed: {e}"),
                Err(e) => eprintln!("board: scan task: {e}"),
            }
            tokio::time::sleep(EVERY).await;
        }
    }
}
