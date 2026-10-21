//! The buyer's history before registration (HNK-26.T8, HNK-20, SEQ-03 part 2): when the private
//! mandate asks for it, the node sends the buyer a `history.request` instead of the commitment
//! opening. The buyer answers with `history.chain`: its certificates 0..k-1 and certificate k for
//! this invoice and this financier. The node checks the chain against its latest board scan
//! (`jitsuin_flow::history::check_buyer`): every earlier invoice anchored by exactly one register
//! entry, settled or still open, no default, no certificate held back. The register entry must
//! then carry certificate k's tag, so this invoice joins the buyer's anchored history.
//!
//! Settlements count only from financiers in the allowlist: this node and the financiers of the
//! provider's signed directory (D-47), whose signature is checked here.

use ed25519_dalek::SigningKey;
use jitsuin_board::history::{HistoryReport, MinimumStandard};
use jitsuin_board::{BoardRecord, SettledRecord};
use jitsuin_core::{HistoryCert, Invoice};
use jitsuin_flow::history::{check_buyer, HistoryPolicy};
use serde_json::{json, Value};

use crate::mandate::PrivateMandate;
use crate::message::{self, hex, unhex};

/// The signing key of the node provider (jitsuinfi-frontend `src/lib/provider.ts`), which signs
/// the financier directory; `PROVIDER_SIGNER_PK` overrides it.
pub const PROVIDER_SIGNER_PK: &str =
    "48eebdb1265d23d0a93bc563b875a6b5440a0e6567db3b91ad7f80a437ded4ec";
pub const DIRECTORY_URL: &str = "https://jitsuinfi.vercel.app/directory.json";

/// Whether the mandate asks for the buyer's history before an offer goes ahead.
pub fn needed(m: &PrivateMandate) -> bool {
    m.min_buyer_history.is_some() || m.buyer_kyc
}

/// The minimum standard from the private mandate: no default ever, at least the on-time share once
/// established; with a history rule, a buyer is established after that many settled invoices and
/// a new buyer is refused, otherwise a new buyer is welcome.
pub fn standard(m: &PrivateMandate) -> MinimumStandard {
    MinimumStandard {
        max_defaults: 0,
        min_on_time_pct: m.on_time_pct(),
        established_after: m.min_buyer_history.unwrap_or(1),
        new_buyer_limit_zat: if m.min_buyer_history.is_some_and(|k| k > 0) {
            0
        } else {
            u64::MAX
        },
    }
}

/// This node's key plus the keys of the provider's signed directory; only this node's key when
/// the directory cannot be read or its signature does not hold.
pub async fn allowlist(own: [u8; 32], trusted: &[String]) -> Vec<[u8; 32]> {
    let mut keys = vec![own];
    for k in trusted {
        if let Ok(pk) = unhex::<32>(k) {
            if !keys.contains(&pk) {
                keys.push(pk);
            }
        }
    }
    let url = std::env::var("DIRECTORY_URL").unwrap_or_else(|_| DIRECTORY_URL.into());
    let signer = std::env::var("PROVIDER_SIGNER_PK").unwrap_or_else(|_| PROVIDER_SIGNER_PK.into());
    let Ok(resp) = reqwest::get(&url).await else {
        return keys;
    };
    let Ok(d) = resp.json::<Value>().await else {
        return keys;
    };
    if !crate::directory::verify(&d, &signer) {
        return keys;
    }
    for f in d["financiers"].as_array().into_iter().flatten() {
        if let Some(Ok(pk)) = f["financier_pk"].as_str().map(unhex::<32>) {
            if !keys.contains(&pk) {
                keys.push(pk);
            }
        }
    }
    keys
}

/// `history.request` to the buyer for invoice `n`.
pub fn request_message(
    key: &SigningKey,
    me: &[u8; 32],
    to: &[u8; 32],
    n: &str,
    nonce: [u8; 16],
    now: u64,
) -> Result<Vec<u8>, String> {
    let body =
        json!({ "financier_pk": hex(&key.verifying_key().to_bytes()), "nonce": hex(&nonce) });
    let mut h = message::draft("history.request", me, to, Some(n), body, &[], now);
    message::sign(&mut h, key);
    message::encode(&h, &[])
}

/// The certificates of a `history.chain` for invoice `n`, oldest first; the last is this invoice's.
pub fn read_chain(h: &Value, n: &str) -> Result<Vec<HistoryCert>, String> {
    use base64::Engine;
    if h["type"] != "history.chain" || h["n"].as_str() != Some(n) {
        return Err("not the buyer history of this deal".into());
    }
    let certs: Vec<HistoryCert> = h["body"]["certs"]
        .as_array()
        .ok_or("the history has no certificates")?
        .iter()
        .map(|c| {
            c.as_str()
                .and_then(|s| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(s)
                        .ok()
                })
                .and_then(|b| HistoryCert::from_bytes(&b).ok())
                .ok_or_else(|| "a certificate does not decode".to_string())
        })
        .collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err("the history has no certificates".into());
    }
    Ok(certs)
}

/// What the check found, for the console.
pub fn summary(r: &HistoryReport, k: usize) -> String {
    format!(
        "{} earlier invoice{}: {} on time, {} late, {} open, {} defaulted",
        k,
        if k == 1 { "" } else { "s" },
        r.on_time,
        r.late,
        r.open,
        r.defaults
    )
}

/// Checks the chain for `invoice` and returns the tag the register entry must carry, with a
/// summary. `registered` says whether the identity key is in the KYC registry.
#[allow(clippy::too_many_arguments)]
pub fn check(
    certs: &[HistoryCert],
    invoice: &Invoice,
    financier_pk: &[u8; 32],
    mandate: &PrivateMandate,
    allowlist: Vec<[u8; 32]>,
    registered: impl Fn(&[u8; 32]) -> bool,
    scan: (&[BoardRecord], &[SettledRecord]),
    today: u32,
) -> Result<([u8; 32], String), String> {
    let (new, earlier) = certs
        .split_last()
        .ok_or("no certificate for this invoice")?;
    if mandate.buyer_kyc && !registered(&new.identity_pk) {
        return Err("the buyer's identity key is not in your KYC list".into());
    }
    let policy = HistoryPolicy {
        allowlist,
        standard: standard(mandate),
        grace_days: mandate.grace(),
    };
    let (report, tag) = check_buyer(
        earlier,
        new,
        invoice,
        financier_pk,
        &policy,
        scan.0,
        scan.1,
        today,
    )
    .map_err(|e| format!("the buyer's history does not pass: {e}"))?;
    Ok((tag, summary(&report, earlier.len())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mandate_decides_when_and_how_history_counts() {
        let none = PrivateMandate::default();
        assert!(!needed(&none));
        assert_eq!(standard(&none).new_buyer_limit_zat, u64::MAX);
        let strict = PrivateMandate {
            min_buyer_history: Some(3),
            ..Default::default()
        };
        assert!(needed(&strict));
        let s = standard(&strict);
        assert_eq!((s.established_after, s.new_buyer_limit_zat), (3, 0));
        assert!(needed(&PrivateMandate {
            buyer_kyc: true,
            ..Default::default()
        }));
    }

    #[test]
    fn a_chain_is_read_only_for_its_own_deal() {
        let h = json!({ "type": "history.chain", "n": "aa", "body": { "certs": ["!!"] } });
        assert!(read_chain(&h, "bb").is_err());
        assert!(read_chain(&h, "aa")
            .unwrap_err()
            .contains("does not decode"));
        let empty = json!({ "type": "history.chain", "n": "aa", "body": { "certs": [] } });
        assert!(read_chain(&empty, "aa").is_err());
    }
}
