//! The node's relay client (HNK-26.T4): registers the financier mailbox at the relay
//! (jitsuinfi-backend), seals messages to a counterparty's mailbox, and reads its own. The same
//! protocol as the web app's `src/lib/relay.ts`; the mailbox key comes from the node's master key
//! (`NodeKeys::mailbox`) instead of a passkey PRF.

use jitsuin_core::mailbox::{self, MailboxKeys, Purpose};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::message::{self, hex, unhex, Message};

pub struct Relay {
    base: String,
    http: reqwest::Client,
}

#[derive(Debug)]
pub struct RelayError(pub String);

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RelayError {}

type Result<T> = std::result::Result<T, RelayError>;

fn err(e: impl std::fmt::Display) -> RelayError {
    RelayError(e.to_string())
}

/// One opened message from the mailbox.
pub struct Received {
    pub relay_id: String,
    pub received_at: String,
    pub message: Message,
    /// The header signature holds; the expected signer is checked by the code that handles it.
    pub signature_ok: bool,
}

#[derive(Deserialize)]
struct Challenge {
    challenge_id: String,
    eph_pk: String,
    nonce: String,
}

#[derive(Deserialize)]
struct Listed {
    id: String,
    received_at: String,
}

impl Relay {
    pub fn new(base: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .https_only(
                !base.starts_with("http://127.0.0.1") && !base.starts_with("http://localhost"),
            )
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("jitsuin-node")
            .build()
            .map_err(err)?;
        Ok(Relay {
            base: base.trim_end_matches('/').to_string(),
            http,
        })
    }

    async fn call(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        let r = req
            .send()
            .await
            .map_err(|_| RelayError("the relay cannot be reached".into()))?;
        if r.status().is_success() {
            return Ok(r);
        }
        let status = r.status().as_u16();
        let msg = r
            .json::<Value>()
            .await
            .ok()
            .and_then(|j| j["error"].as_str().map(String::from));
        Err(RelayError(match msg {
            Some(m) => format!("relay: {m}"),
            None => format!("the relay answered {status}"),
        }))
    }

    async fn json(&self, req: reqwest::RequestBuilder) -> Result<Value> {
        self.call(req).await?.json().await.map_err(err)
    }

    async fn proven(&self, me: &MailboxKeys, purpose: Purpose) -> Result<Value> {
        let ch: Challenge = serde_json::from_value(
            self.json(
                self.http
                    .post(format!("{}/api/mailbox/challenge", self.base))
                    .json(&json!({ "mailbox_pk": hex(&me.public()), "purpose": purpose.as_str() })),
            )
            .await?,
        )
        .map_err(err)?;
        let eph = unhex::<32>(&ch.eph_pk).map_err(err)?;
        let nonce = unhex::<32>(&ch.nonce).map_err(err)?;
        let proof = me.proof(purpose, &eph, &nonce).map_err(err)?;
        Ok(json!({ "challenge_id": ch.challenge_id, "proof": hex(&proof) }))
    }

    /// Registers the mailbox (harmless when it exists) and checks the relay's `mailbox_id`.
    pub async fn ensure_mailbox(&self, me: &MailboxKeys) -> Result<()> {
        let mut body = self.proven(me, Purpose::Register).await?;
        body["mailbox_pk"] = hex(&me.public()).into();
        let r = self
            .json(
                self.http
                    .post(format!("{}/api/mailbox", self.base))
                    .json(&body),
            )
            .await?;
        if r["mailbox_id"].as_str() != Some(hex(&me.id()).as_str()) {
            return Err(RelayError(
                "the relay computed another mailbox id; do not use it".into(),
            ));
        }
        Ok(())
    }

    #[allow(dead_code)] // the deal API sends (HNK-26.T5+)
    /// Seals an encoded message to `to_pk` and drops it in that mailbox; returns the relay's id.
    pub async fn send(&self, to_pk: &[u8; 32], plaintext: &[u8]) -> Result<String> {
        let mut eph = [0u8; 32];
        rand::rng().fill_bytes(&mut eph);
        let sealed = mailbox::seal(to_pk, &eph, plaintext).map_err(err)?;
        eph.fill(0);
        let r = self
            .json(
                self.http
                    .post(format!(
                        "{}/api/mailbox/{}/messages",
                        self.base,
                        hex(&mailbox::mailbox_id(to_pk))
                    ))
                    .header("Content-Type", "application/octet-stream")
                    .body(sealed),
            )
            .await?;
        r["message_id"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| RelayError("the relay gave no message id".into()))
    }

    async fn token(&self, me: &MailboxKeys) -> Result<String> {
        let body = self.proven(me, Purpose::Read).await?;
        let r = self
            .json(
                self.http
                    .post(format!("{}/api/mailbox/{}/read", self.base, hex(&me.id())))
                    .json(&body),
            )
            .await?;
        r["token"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| RelayError("the relay gave no read token".into()))
    }

    /// Every message in the mailbox, opened and checked; returns the read token for removals and
    /// the number of messages refused (do not open, malformed, or addressed elsewhere).
    pub async fn receive(&self, me: &MailboxKeys) -> Result<(Vec<Received>, usize, String)> {
        let token = self.token(me).await?;
        let id = hex(&me.id());
        let list: Vec<Listed> = serde_json::from_value(
            self.json(
                self.http
                    .get(format!("{}/api/mailbox/{id}/messages", self.base))
                    .bearer_auth(&token),
            )
            .await?["messages"]
                .take(),
        )
        .map_err(err)?;
        let mut out = Vec::new();
        let mut refused = 0;
        for m in list {
            let sealed = self
                .call(
                    self.http
                        .get(format!("{}/api/mailbox/{id}/messages/{}", self.base, m.id))
                        .bearer_auth(&token),
                )
                .await?
                .bytes()
                .await
                .map_err(err)?;
            match me
                .open(&sealed)
                .map_err(err)
                .and_then(|p| message::decode(&p, &id).map_err(RelayError))
            {
                Ok(message) => {
                    let signature_ok = message.header.get("sig").is_none()
                        || message::verify(&message.header, None);
                    out.push(Received {
                        relay_id: m.id,
                        received_at: m.received_at,
                        message,
                        signature_ok,
                    });
                }
                Err(_) => refused += 1,
            }
        }
        Ok((out, refused, token))
    }

    #[allow(dead_code)] // the deal API removes handled messages (HNK-26.T5+)
    /// Removes a message after it was used.
    pub async fn remove(&self, me: &MailboxKeys, relay_id: &str, token: &str) -> Result<()> {
        self.call(
            self.http
                .delete(format!(
                    "{}/api/mailbox/{}/messages/{relay_id}",
                    self.base,
                    hex(&me.id())
                ))
                .bearer_auth(token),
        )
        .await?;
        Ok(())
    }
}

/// The financier's contact card, the same format as the web app's `src/lib/contact.ts`:
/// `jitsuin-contact-v1:` + base64url(JSON {v, role, mailbox_pk, fingerprint}).
pub fn contact_card(mailbox_pk: &[u8; 32], financier_pk: &[u8; 32]) -> String {
    use base64::Engine;
    let card = json!({ "v": 1, "role": "financier", "mailbox_pk": hex(mailbox_pk), "fingerprint": fingerprint(financier_pk) });
    format!(
        "jitsuin-contact-v1:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(card.to_string())
    )
}

/// The node's key fingerprint, in the app's shape (10 bytes, base32, groups of 4). The node has
/// one public financier key, so the fingerprint is of that key: SHA-256("jitsuin-fingerprint-v1:
/// financier:" ‖ financier_pk), first 10 bytes. Anyone holding `financier_pk` can recompute it.
pub fn fingerprint(financier_pk: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::new()
        .chain_update(b"jitsuin-fingerprint-v1:financier:")
        .chain_update(financier_pk)
        .finalize();
    message::base32_groups(&d[..10])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_card_decodes_like_contact_ts() {
        use base64::Engine;
        let card = contact_card(&[7; 32], &[9; 32]);
        let body = card.strip_prefix("jitsuin-contact-v1:").unwrap();
        let v: Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(body)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(v["role"], "financier");
        assert_eq!(v["mailbox_pk"], hex(&[7; 32]));
        let f = v["fingerprint"].as_str().unwrap();
        assert_eq!(f.len(), 19, "16 base32 characters in 4 groups");
        assert!(f.split('-').all(|g| g.len() == 4));
    }
}
