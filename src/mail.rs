//! The financier's mailbox for the console (HNK-26.T4, BL-D21-10): `/node/mail/*` reads the
//! node's own mailbox at the relay with the node's mailbox key, so the console never holds a key.
//! The last listing is kept in memory, so attachments and removals refer to what the operator saw.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use jitsuin_core::mailbox::MailboxKeys;
use serde_json::{json, Value};

use crate::relay::{Received, Relay, RelayError};

/// Read tokens last 10 minutes at the relay; renew a little earlier.
const TOKEN_TTL: Duration = Duration::from_secs(9 * 60);

pub struct Mail {
    relay: Relay,
    keys: MailboxKeys,
    seen: Mutex<HashMap<String, Received>>,
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
    pub async fn list(&self) -> Result<(Vec<Value>, usize), RelayError> {
        let (got, refused, token) = self.relay.receive(&self.keys).await?;
        *self.token.lock().unwrap() = Some((token, Instant::now()));
        let mut out: Vec<Value> = got.iter().map(summary).collect();
        out.sort_by(|a, b| b["received_at"].as_str().cmp(&a["received_at"].as_str()));
        let mut seen = self.seen.lock().unwrap();
        seen.clear();
        seen.extend(got.into_iter().map(|r| (r.relay_id.clone(), r)));
        Ok((out, refused))
    }

    /// Attachment `index` of a listed message, with its file name.
    pub fn attachment(&self, relay_id: &str, index: usize) -> Option<(String, Vec<u8>)> {
        let seen = self.seen.lock().unwrap();
        let r = seen.get(relay_id)?;
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
        Some(seen.get(relay_id)?.message.header.clone())
    }

    /// Seals an encoded message to `to_pk` at the relay.
    pub async fn send(&self, to_pk: &[u8; 32], plaintext: &[u8]) -> Result<String, RelayError> {
        self.relay.send(to_pk, plaintext).await
    }

    /// Removes a listed message from the relay.
    pub async fn remove(&self, relay_id: &str) -> Result<bool, RelayError> {
        if !self.seen.lock().unwrap().contains_key(relay_id) {
            return Ok(false);
        }
        let token = match self.token.lock().unwrap().clone() {
            Some((t, at)) if at.elapsed() < TOKEN_TTL => Some(t),
            _ => None,
        };
        let token = match token {
            Some(t) => t,
            None => {
                let t = self.relay.read_token(&self.keys).await?;
                *self.token.lock().unwrap() = Some((t.clone(), Instant::now()));
                t
            }
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
