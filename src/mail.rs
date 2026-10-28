//! The financier's mailbox for the console (HNK-26.T4, BL-D21-10): `/node/mail/*` reads the
//! node's own mailbox at the relay with the node's mailbox key, so the console never holds a key.
//! The last listing is kept in memory, so attachments and removals refer to what the operator saw.
//!
//! Offer latency (E2E runs 4 and 5: an offer took 44 s, then 62 s, to reach the Desk): every
//! listing used to prove ownership again (challenge, read token) and download every message in
//! the mailbox one after another, PDFs included, so each listing grew with the mailbox (30 days,
//! up to 200 messages of up to 4 MiB). Relay messages never change, so a message is now fetched
//! and opened once and kept while the relay lists it, new ones are fetched side by side, and the
//! read token is reused while it is valid: a listing with nothing new is one request.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use jitsuin_core::mailbox::MailboxKeys;
use serde_json::{json, Value};

use crate::relay::{self, Listed, Received, Relay, RelayError};

/// Read tokens last 10 minutes at the relay; renew a little earlier.
const TOKEN_TTL: Duration = Duration::from_secs(9 * 60);
/// New messages fetched at once from the relay.
const FETCH_AT_ONCE: usize = 8;

pub struct Mail {
    relay: Relay,
    keys: MailboxKeys,
    /// The messages of the last listing by relay id, opened once (`None`: refused).
    seen: Mutex<HashMap<String, Option<Received>>>,
    token: Mutex<Option<(String, Instant)>>,
}

/// What the console shows of one message: its header fields and the attachment names and sizes.
fn summary(r: &Received) -> Value {
    let h = &r.message.header;
    json!({
        "relay_id": r.relay_id,
        "received_at": r.received_at,
        "type": h["type"],
        "from": h["from"],
        "n": h["n"],
        "sent_at": h["sent_at"],
        "body": h["body"],
        "signer": h["signer"],
        "signature_ok": r.signature_ok,
        "attachments": h["attachments"],
    })
}

impl Mail {
    pub fn new(relay: Relay, keys: MailboxKeys) -> Self {
        Mail {
            relay,
            keys,
            seen: Mutex::new(HashMap::new()),
            token: Mutex::new(None),
        }
    }

    /// Every message in the mailbox, opened and checked, newest first; and how many were refused.
    /// Only messages not seen before are fetched (`seen`).
    pub async fn list(&self) -> Result<(Vec<Value>, usize), RelayError> {
        let cached = match self.cached_token() {
            // an expired or revoked token: prove ownership again below
            Some(t) => self.relay.list(&self.keys, &t).await.ok().map(|l| (l, t)),
            None => None,
        };
        let (listing, token) = match cached {
            Some(x) => x,
            None => {
                let t = self.fresh_token().await?;
                (self.relay.list(&self.keys, &t).await?, t)
            }
        };
        let mailbox_id = crate::message::hex(&self.keys.id());
        let new: Vec<&Listed> = {
            let seen = self.seen.lock().unwrap();
            listing
                .iter()
                .filter(|m| !seen.contains_key(&m.id))
                .collect()
        };
        let mut opened: HashMap<String, Option<Received>> = HashMap::new();
        for chunk in new.chunks(FETCH_AT_ONCE) {
            let mut set = tokio::task::JoinSet::new();
            for m in chunk {
                let (relay, mailbox_id, token, id) = (
                    self.relay.clone(),
                    mailbox_id.clone(),
                    token.clone(),
                    m.id.clone(),
                );
                set.spawn(async move {
                    let sealed = relay.fetch(&mailbox_id, &token, &id).await;
                    (id, sealed)
                });
            }
            while let Some(done) = set.join_next().await {
                let (id, sealed) = done.map_err(|e| RelayError(e.to_string()))?;
                let sealed = sealed?;
                let m = chunk.iter().find(|m| m.id == id).expect("listed");
                let listed = Listed {
                    id: m.id.clone(),
                    received_at: m.received_at.clone(),
                };
                opened.insert(id, relay::open(&self.keys, listed, &sealed));
            }
        }
        let mut seen = self.seen.lock().unwrap();
        let mut kept: HashMap<String, Option<Received>> = HashMap::new();
        for m in &listing {
            if let Some(r) = opened.remove(&m.id).or_else(|| seen.remove(&m.id)) {
                kept.insert(m.id.clone(), r);
            }
        }
        *seen = kept;
        let refused = seen.values().filter(|r| r.is_none()).count();
        let mut out: Vec<Value> = seen.values().flatten().map(summary).collect();
        out.sort_by(|a, b| b["received_at"].as_str().cmp(&a["received_at"].as_str()));
        Ok((out, refused))
    }

    fn cached_token(&self) -> Option<String> {
        match self.token.lock().unwrap().clone() {
            Some((t, at)) if at.elapsed() < TOKEN_TTL => Some(t),
            _ => None,
        }
    }

    async fn fresh_token(&self) -> Result<String, RelayError> {
        let t = self.relay.read_token(&self.keys).await?;
        *self.token.lock().unwrap() = Some((t.clone(), Instant::now()));
        Ok(t)
    }

    /// Attachment `index` of a listed message, with its file name.
    pub fn attachment(&self, relay_id: &str, index: usize) -> Option<(String, Vec<u8>)> {
        let seen = self.seen.lock().unwrap();
        let r = seen.get(relay_id)?.as_ref()?;
        let bytes = r.message.attachments.get(index)?.clone();
        let name = r.message.header["attachments"][index]["name"]
            .as_str()
            .unwrap_or("attachment.pdf")
            .to_string();
        Some((name, bytes))
    }

    /// The header of a listed message.
    pub fn header(&self, relay_id: &str) -> Option<serde_json::Value> {
        let seen = self.seen.lock().unwrap();
        Some(seen.get(relay_id)?.as_ref()?.message.header.clone())
    }

    /// Seals an encoded message to `to_pk` at the relay.
    pub async fn send(&self, to_pk: &[u8; 32], plaintext: &[u8]) -> Result<String, RelayError> {
        self.relay.send(to_pk, plaintext).await
    }

    /// Removes a listed message from the relay.
    pub async fn remove(&self, relay_id: &str) -> Result<bool, RelayError> {
        if !self
            .seen
            .lock()
            .unwrap()
            .get(relay_id)
            .is_some_and(|r| r.is_some())
        {
            return Ok(false);
        }
        let token = match self.cached_token() {
            Some(t) => t,
            None => self.fresh_token().await?,
        };
        self.relay.remove(&self.keys, relay_id, &token).await?;
        self.seen.lock().unwrap().remove(relay_id);
        Ok(true)
    }
}

/// A safe `Content-Disposition` file name: letters, digits, dot, dash and underscore only.
pub fn safe_name(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || ".-_".contains(c) {
                c
            } else {
                '_'
            }
        })
        .take(100)
        .collect();
    if s.is_empty() {
        "attachment.pdf".into()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_cannot_break_the_header() {
        assert_eq!(safe_name("letter.pdf"), "letter.pdf");
        assert_eq!(
            safe_name("a\"; filename=x.html\r\n"),
            "a___filename_x.html__"
        );
        assert_eq!(safe_name(""), "attachment.pdf");
    }
}

/// Listing latency against a local relay only (jitsuinfi-backend `node src/server.ts`, in
/// memory): `JITSUIN_TEST_RELAY=http://127.0.0.1:8787 cargo test mailbox_latency -- --ignored
/// --nocapture`. Never point it at the production relay.
#[cfg(test)]
mod latency {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn mailbox_latency() {
        let Ok(url) = std::env::var("JITSUIN_TEST_RELAY") else {
            return;
        };
        assert!(url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost"));
        let count: usize = std::env::var("MESSAGES")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(40);
        let size: usize = std::env::var("BYTES")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(300_000);
        let mut prf = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut prf);
        let keys = MailboxKeys::from_prf(&prf);
        let relay = Relay::new(&url).unwrap();
        relay.ensure_mailbox(&keys).await.unwrap();
        let body = vec![7u8; size];
        for _ in 0..count {
            relay.send(&keys.public(), &body).await.unwrap();
        }
        let t = Instant::now();
        let (_, refused, _) = relay.receive(&keys).await.unwrap();
        let full = t.elapsed();
        let mail = Mail::new(relay.clone(), MailboxKeys::from_prf(&prf));
        let t = Instant::now();
        mail.list().await.unwrap();
        let cold = t.elapsed();
        let t = Instant::now();
        mail.list().await.unwrap();
        let warm = t.elapsed();
        relay.send(&keys.public(), &body).await.unwrap();
        let t = Instant::now();
        let (_, r2) = mail.list().await.unwrap();
        let one_new = t.elapsed();
        assert_eq!((refused, r2), (count, count + 1));
        println!(
            "{count} messages of {size} B: old listing {full:?}, first listing {cold:?}, \
             nothing new {warm:?}, one new {one_new:?}"
        );
    }
}
