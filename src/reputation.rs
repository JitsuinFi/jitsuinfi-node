//! Financier reputation by provider attestation (HNK-30.T21, D-48). The board cannot link two
//! entries to one financier (each commitment has a fresh salt), so a financier proves its own
//! record: its node sends the provider the `(N, salt)` of its deals, sealed and signed with the
//! financier key. The provider checks each against the public board (the register entry for N
//! carries `BLAKE2b(financier_pk ‖ salt)`, and a `settled` entry carries `settled_tag(N)` with its
//! on-time flag) and signs only coarse classes into the financier's directory listing.
//!
//! Limit (disclosed in D-48): a financier can pump its record by dealing with itself (its own
//! invoices, buyer keys and settlements), so the classes are a signal, not proof of real business.

use std::collections::HashSet;

use base64::Engine;
use ed25519_dalek::SigningKey;
use jitsuin_core::{
    commitment_opening, financier_commitment, settled_tag, BoardEntry, SettledEntry,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::message::{self, hex, unhex};

/// A deal's fingerprint N and the salt behind this financier's commitment for it.
pub type Deal = ([u8; 32], [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reputation {
    /// "1-4", "5-19" or "20+": deals registered for this financier and settled.
    pub settled: String,
    /// "95+", "80-95" or "<80": the share of those settled on time, in percent.
    pub on_time: String,
    /// The board was read up to this height.
    pub up_to_height: u64,
    pub attested_at: u64,
}

/// What the board shows for these deals of `financier_pk`: (settled, settled on time).
pub fn count(
    board_json: &str,
    financier_pk: &[u8; 32],
    deals: &[Deal],
) -> Result<(usize, usize, u64), String> {
    let rows: Vec<Value> =
        serde_json::from_str(board_json).map_err(|e| format!("board data: {e}"))?;
    let mut registered = HashSet::new();
    let mut settled = Vec::new();
    let mut top = 0u64;
    for r in &rows {
        top = top.max(r["height"].as_u64().unwrap_or(0));
        let Some(memo) = r["memo"].as_str().and_then(|m| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(m.trim_end_matches('='))
                .ok()
        }) else {
            continue;
        };
        if let Ok(e) = BoardEntry::from_memo_bytes(&memo) {
            registered.insert((e.nullifier, e.financier_commitment));
        } else if let Ok(s) = SettledEntry::from_memo_bytes(&memo) {
            settled.push((s.tag, s.on_time()));
        }
    }
    let mut seen = HashSet::new();
    let (mut done, mut on_time) = (0, 0);
    for (n, salt) in deals {
        if !seen.insert(*n) || !registered.contains(&(*n, financier_commitment(financier_pk, salt)))
        {
            continue;
        }
        let tag = settled_tag(n);
        if let Some((_, ok)) = settled.iter().find(|(t, _)| *t == tag) {
            done += 1;
            if *ok {
                on_time += 1;
            }
        }
    }
    Ok((done, on_time, top))
}

/// The published classes; `None` when nothing is settled yet.
pub fn classes(settled: usize, on_time: usize, up_to_height: u64, now: u64) -> Option<Reputation> {
    if settled == 0 {
        return None;
    }
    let pct = on_time * 100 / settled;
    Some(Reputation {
        settled: match settled {
            1..=4 => "1-4",
            5..=19 => "5-19",
            _ => "20+",
        }
        .into(),
        on_time: if pct >= 95 {
            "95+"
        } else if pct >= 80 {
            "80-95"
        } else {
            "<80"
        }
        .into(),
        up_to_height,
        attested_at: now,
    })
}

/// The `financier.reputation_request` a node sends the provider: the `(N, salt)` of its deals,
/// the salt derived from the financier key as in the register entry (P-08).
pub fn request_message(
    key: &SigningKey,
    my_mailbox_pk: &[u8; 32],
    to: &[u8; 32],
    ns: &[[u8; 32]],
    now: u64,
) -> Result<Vec<u8>, String> {
    let deals: Vec<Value> = ns
        .iter()
        .map(|n| json!({ "n": hex(n), "salt": hex(&commitment_opening(key, n).0) }))
        .collect();
    let mut h = message::draft(
        "financier.reputation_request",
        my_mailbox_pk,
        to,
        None,
        json!({ "deals": deals }),
        &[],
        now,
    );
    message::sign(&mut h, key);
    message::encode(&h, &[])
}

/// A received request, checked: signed by the financier key; returns that key and the deals.
pub fn read_request(h: &Value) -> Result<([u8; 32], Vec<Deal>), String> {
    if h["type"] != "financier.reputation_request" {
        return Err("not a reputation request".into());
    }
    let signer = h["signer"].as_str().ok_or("the request is not signed")?;
    if !message::verify(h, Some(signer)) {
        return Err("the request's signature does not hold".into());
    }
    let deals = h["body"]["deals"]
        .as_array()
        .ok_or("the request lists no deals")?
        .iter()
        .map(|d| {
            Ok((
                unhex::<32>(d["n"].as_str().unwrap_or_default())?,
                unhex::<32>(d["salt"].as_str().unwrap_or_default())?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((unhex::<32>(signer)?, deals))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_are_coarse() {
        assert_eq!(classes(0, 0, 1, 1), None);
        let r = classes(7, 7, 10, 11).unwrap();
        assert_eq!((r.settled.as_str(), r.on_time.as_str()), ("5-19", "95+"));
        let r = classes(25, 21, 10, 11).unwrap();
        assert_eq!((r.settled.as_str(), r.on_time.as_str()), ("20+", "80-95"));
        assert_eq!(classes(3, 1, 1, 1).unwrap().on_time, "<80");
    }

    #[test]
    fn the_request_round_trips_and_is_bound_to_its_key() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let to = [9u8; 32];
        let bytes = request_message(&key, &[7; 32], &to, &[[1; 32], [2; 32]], 5).unwrap();
        let m = message::decode(&bytes, &hex(&jitsuin_core::mailbox::mailbox_id(&to))).unwrap();
        let (pk, deals) = read_request(&m.header).unwrap();
        assert_eq!(pk, key.verifying_key().to_bytes());
        assert_eq!(deals[0].1, commitment_opening(&key, &[1; 32]).0);
        let mut forged = m.header.clone();
        forged["body"]["deals"][0]["salt"] = hex(&[0; 32]).into();
        assert!(read_request(&forged).is_err());
    }

    #[test]
    fn only_this_financiers_settled_deals_count() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let pk = key.verifying_key().to_bytes();
        // an empty board counts nothing
        assert_eq!(
            count(
                "[]",
                &pk,
                &[([1; 32], commitment_opening(&key, &[1; 32]).0)]
            )
            .unwrap(),
            (0, 0, 0)
        );
    }
}
