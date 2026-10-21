//! Offers (HNK-26.T5, BL-D23-02, SEQ-03 part 1): a supplier's `deal.offer` arrives sealed in the
//! node's mailbox. The node reads it only when the supplier signed the message with the invoice's
//! supplier key and the buyer signed exactly that invoice (`verify_invoice`), so a forged offer is
//! refused before anything is saved and before any money moves (F3.03).
//!
//! When the operator accepts, the node saves the deal terms (`deals/<N>.json` in the volume) and
//! sends the supplier its commitment opening (`deal.commitment_opening`). The assignment letter
//! and the deal state machine (`Flow`) start from these terms in the next step.

use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine;
use ed25519_dalek::{Signature, SigningKey};
use jitsuin_core::{commitment_opening, nullifier, verify_invoice, Invoice};
use jitsuin_flow::financier::deal_classes;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::message::{self, hex, unhex};

/// A checked offer: every field below was verified against the signed invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub n: String,
    pub invoice: Invoice,
    /// The invoice as sent (base64url of its canonical bytes).
    pub invoice_b64: String,
    pub buyer_signature: [u8; 64],
    /// The advance the supplier asks for.
    pub advance_zat: u64,
    pub supplier_address: String,
    /// The supplier's reply mailbox, from the signed header.
    pub supplier_mailbox_pk: [u8; 32],
    /// The buyer's mailbox, when the supplier gave it: the letter goes there too (HNK-26.T16).
    pub buyer_mailbox_pk: Option<[u8; 32]>,
}

/// The terms the operator accepted, saved before the reply is sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accepted {
    pub n: String,
    pub invoice: String,
    pub buyer_signature: String,
    pub advance_zat: u64,
    pub min_confirmations: u32,
    pub supplier_address: String,
    pub supplier_mailbox_pk: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buyer_mailbox_pk: Option<String>,
    pub discount: u8,
    pub tenor: u8,
    /// Seconds since the Unix epoch.
    pub accepted_at: u64,
}

/// A shielded address as the assignment letter takes it: ASCII letters and digits, at most 512.
fn address_ok(a: &str) -> bool {
    !a.is_empty() && a.len() <= 512 && a.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Reads and checks a `deal.offer` header; the error says why it is refused.
pub fn read(header: &Value) -> Result<Offer, String> {
    if header["type"] != "deal.offer" {
        return Err("not a financing offer".into());
    }
    if header["from"]["role"] != "supplier" {
        return Err("the offer does not come from a supplier".into());
    }
    let supplier_mailbox_pk = header["from"]["mailbox_pk"]
        .as_str()
        .ok_or("the offer has no reply mailbox")
        .and_then(|s| unhex::<32>(s).map_err(|_| "the offer has no reply mailbox"))?;
    let body = &header["body"];
    let invoice_b64 = body["invoice"].as_str().ok_or("the offer has no invoice")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(invoice_b64)
        .map_err(|_| "the invoice is not base64url")?;
    let invoice = Invoice::from_canonical_bytes(&bytes)
        .map_err(|e| format!("the invoice does not decode: {e:?}"))?;
    let n = hex(&nullifier(&invoice).map_err(|e| format!("invoice: {e:?}"))?);
    if header["n"].as_str() != Some(n.as_str()) {
        return Err("the offer names another invoice (N differs)".into());
    }
    // The supplier key of this invoice signed the message: nobody else can offer it.
    if !message::verify(header, Some(&hex(&invoice.supplier_ephemeral_pk))) {
        return Err("the supplier's signature does not hold for this invoice".into());
    }
    let buyer_signature = body["buyer_signature"]
        .as_str()
        .and_then(|s| unhex::<64>(s).ok())
        .ok_or("the offer has no buyer signature")?;
    verify_invoice(&invoice, &Signature::from_bytes(&buyer_signature))
        .map_err(|_| "the buyer did not sign this invoice")?;
    let advance_zat = body["advance_zat"]
        .as_u64()
        .filter(|a| *a > 0)
        .ok_or("the offer asks for no advance")?;
    if advance_zat > invoice.amount_zat {
        return Err("the advance asked is more than the invoice amount".into());
    }
    let supplier_address = body["supplier_address"].as_str().unwrap_or_default();
    if !address_ok(supplier_address) {
        return Err("the supplier's address is not a shielded address".into());
    }
    let buyer_mailbox_pk = match body["buyer_mailbox_pk"].as_str() {
        None => None,
        Some(s) => {
            Some(unhex::<32>(s).map_err(|_| "the buyer's mailbox is not 64 hex characters")?)
        }
    };
    Ok(Offer {
        buyer_mailbox_pk,
        n,
        invoice_b64: invoice_b64.to_string(),
        invoice,
        buyer_signature,
        advance_zat,
        supplier_address: supplier_address.to_string(),
        supplier_mailbox_pk,
    })
}

/// What the console shows of an offer: the checked terms, or why it is refused.
pub fn summary(header: &Value, deals: &Path) -> Value {
    match read(header) {
        Ok(o) => json!({
            "ok": true,
            "n": o.n,
            "invoice_id": o.invoice.invoice_id,
            "amount_zat": o.invoice.amount_zat,
            "issue_date": o.invoice.issue_date,
            "due_date": o.invoice.due_date,
            "advance_zat": o.advance_zat,
            "supplier_address": o.supplier_address,
            "accepted": load(deals, &o.n),
        }),
        Err(problem) => json!({ "ok": false, "problem": problem }),
    }
}

fn path(deals: &Path, n: &str) -> PathBuf {
    deals.join(format!("{n}.json"))
}

/// The accepted terms for N, if any.
pub fn load(deals: &Path, n: &str) -> Option<Accepted> {
    serde_json::from_slice(&std::fs::read(path(deals, n)).ok()?).ok()
}

#[derive(Debug, PartialEq, Eq)]
pub enum AcceptError {
    /// The operator's terms are not valid (shown as is).
    Terms(&'static str),
    /// This invoice was accepted before: one deal per invoice.
    Taken,
    Io(String),
}

/// Checks the operator's terms and saves them, once per invoice. `today` is days since the epoch.
pub fn accept(
    deals: &Path,
    o: &Offer,
    advance_zat: u64,
    min_confirmations: u32,
    today: u32,
    now: u64,
) -> Result<Accepted, AcceptError> {
    if advance_zat == 0 {
        return Err(AcceptError::Terms("the advance must be more than zero"));
    }
    if advance_zat > o.advance_zat {
        return Err(AcceptError::Terms(
            "the advance cannot be more than the supplier asked",
        ));
    }
    if !(1..=100).contains(&min_confirmations) {
        return Err(AcceptError::Terms("confirmations must be from 1 to 100"));
    }
    let (discount, tenor) = deal_classes(&o.invoice, advance_zat, today);
    let a = Accepted {
        n: o.n.clone(),
        invoice: o.invoice_b64.clone(),
        buyer_signature: hex(&o.buyer_signature),
        advance_zat,
        min_confirmations,
        supplier_address: o.supplier_address.clone(),
        supplier_mailbox_pk: hex(&o.supplier_mailbox_pk),
        buyer_mailbox_pk: o.buyer_mailbox_pk.map(|b| hex(&b)),
        discount,
        tenor,
        accepted_at: now,
    };
    std::fs::create_dir_all(deals).map_err(|e| AcceptError::Io(e.to_string()))?;
    let mut f = std::fs::OpenOptions::new();
    f.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut f, 0o600);
    let mut file = f.open(path(deals, &o.n)).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => AcceptError::Taken,
        _ => AcceptError::Io(e.to_string()),
    })?;
    file.write_all(&serde_json::to_vec(&a).unwrap())
        .and_then(|_| file.sync_all())
        .map_err(|e| AcceptError::Io(e.to_string()))?;
    Ok(a)
}

/// Undoes [`accept`] when the reply could not be sent, so the operator can try again.
pub fn forget(deals: &Path, n: &str) {
    let _ = std::fs::remove_file(path(deals, n));
}

/// The signed `deal.commitment_opening` for an accepted offer (3.2 to 3.6): the salt behind this
/// financier's commitment, and the deal's index classes, which the supplier may publish or not
/// (D-42).
pub fn opening_message(
    key: &SigningKey,
    my_mailbox_pk: &[u8; 32],
    a: &Accepted,
    history_tag: Option<&str>,
    now: u64,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let to = unhex::<32>(&a.supplier_mailbox_pk)?;
    let n = unhex::<32>(&a.n)?;
    let (salt, _commitment) = commitment_opening(key, &n);
    let mut body = json!({
        "financier_pk": hex(&key.verifying_key().to_bytes()),
        "salt": hex(&salt),
        "discount": a.discount,
        "tenor": a.tenor,
    });
    // HNK-26.T8: the tag of the buyer's certificate for this invoice, which the entry must carry
    if let Some(t) = history_tag {
        body["history_tag"] = t.into();
    }
    let mut header = message::draft(
        "deal.commitment_opening",
        my_mailbox_pk,
        &to,
        Some(&a.n),
        body,
        &[],
        now,
    );
    message::sign(&mut header, key);
    Ok((message::encode(&header, &[])?, to))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitsuin_core::invoice::sign_invoice;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn invoice() -> Invoice {
        Invoice {
            invoice_id: "INV-7".into(),
            supplier_ephemeral_pk: key(1).verifying_key().to_bytes(),
            buyer_pk: key(2).verifying_key().to_bytes(),
            amount_zat: 1_000_000,
            issue_date: 20_000,
            due_date: 20_060,
            terms_hash: [9; 32],
        }
    }

    /// A `deal.offer` as the supplier's browser sends it, signed by `signer`.
    fn offer_header(inv: &Invoice, buyer: &SigningKey, signer: &SigningKey) -> Value {
        // A key other than the buyer's may sign too: that is the forgery the node must catch.
        let sig = sign_invoice(buyer, inv).unwrap_or_else(|_| {
            ed25519_dalek::Signer::sign(buyer, &inv.to_canonical_bytes().unwrap())
        });
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(inv.to_canonical_bytes().unwrap());
        let n = hex(&nullifier(inv).unwrap());
        let mut h = message::draft(
            "deal.offer",
            &[3; 32],
            &[4; 32],
            Some(&n),
            json!({ "invoice": b64, "buyer_signature": hex(&sig.to_bytes()), "advance_zat": 900_000, "supplier_address": "utest1supplier" }),
            &[],
            1,
        );
        h["from"]["role"] = "supplier".into();
        h["from"]["mailbox_pk"] = hex(&[3; 32]).into();
        message::sign(&mut h, signer);
        h
    }

    #[test]
    fn a_signed_offer_on_a_buyer_signed_invoice_is_read() {
        let o = read(&offer_header(&invoice(), &key(2), &key(1))).unwrap();
        assert_eq!(o.advance_zat, 900_000);
        assert_eq!(o.supplier_mailbox_pk, [3; 32]);
        assert_eq!(o.invoice, invoice());
    }

    #[test]
    fn forged_offers_are_refused() {
        // F3.03: another key than the buyer's signed the invoice.
        assert_eq!(
            read(&offer_header(&invoice(), &key(5), &key(1))).unwrap_err(),
            "the buyer did not sign this invoice"
        );
        // Someone other than the invoice's supplier key sent it.
        assert!(read(&offer_header(&invoice(), &key(2), &key(6)))
            .unwrap_err()
            .contains("supplier's signature"));
        // The body was changed after signing.
        let mut h = offer_header(&invoice(), &key(2), &key(1));
        h["body"]["advance_zat"] = 999_999.into();
        assert!(read(&h).unwrap_err().contains("supplier's signature"));
        // An advance above the invoice amount.
        let mut h = offer_header(&invoice(), &key(2), &key(1));
        h["body"]["advance_zat"] = 2_000_000.into();
        message::sign(&mut h, &key(1));
        assert!(read(&h).unwrap_err().contains("more than the invoice"));
    }

    /// A `deal.offer` made by the supplier page's own code (wasm keys from fixed test masters,
    /// relay.ts `draft` + `signInWasm`, relay-message.ts `encodeMessage`): the node reads it.
    #[test]
    fn reads_an_offer_made_by_the_web_app() {
        let raw = include_str!("../tests/vectors/jtsm-deal-offer.hex").trim();
        let bytes: Vec<u8> = (0..raw.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
            .collect();
        let to = hex(&jitsuin_core::mailbox::mailbox_id(&[0xcd; 32]));
        let m = message::decode(&bytes, &to).unwrap();
        let o = read(&m.header).unwrap();
        assert_eq!(o.invoice.invoice_id, "INV-42");
        assert_eq!(o.advance_zat, 45_000_000);
        assert_eq!(o.supplier_mailbox_pk, [0xef; 32]);
    }

    #[test]
    fn an_invoice_is_accepted_once_with_valid_terms() {
        let dir = std::env::temp_dir().join(format!("jitsuin-offer-{}", message::random_id()));
        let o = read(&offer_header(&invoice(), &key(2), &key(1))).unwrap();
        assert_eq!(
            accept(&dir, &o, 900_001, 1, 20_000, 5),
            Err(AcceptError::Terms(
                "the advance cannot be more than the supplier asked"
            ))
        );
        assert!(matches!(
            accept(&dir, &o, 800_000, 0, 20_000, 5),
            Err(AcceptError::Terms(_))
        ));
        let a = accept(&dir, &o, 800_000, 2, 20_000, 5).unwrap();
        assert_eq!(load(&dir, &o.n), Some(a.clone()));
        assert_eq!(
            accept(&dir, &o, 800_000, 2, 20_000, 5),
            Err(AcceptError::Taken)
        );

        // The reply opens to the supplier and carries this financier's salt, signed.
        let fin = key(8);
        let (bytes, to) = opening_message(&fin, &[4; 32], &a, None, 6).unwrap();
        assert_eq!(to, [3; 32]);
        let m = message::decode(&bytes, &hex(&jitsuin_core::mailbox::mailbox_id(&to))).unwrap();
        let fin_pk = hex(&fin.verifying_key().to_bytes());
        assert!(message::verify(&m.header, Some(&fin_pk)));
        let (salt, _) = commitment_opening(&fin, &unhex::<32>(&a.n).unwrap());
        assert_eq!(m.header["body"]["salt"], hex(&salt));
        assert_eq!(m.header["n"], a.n);

        forget(&dir, &o.n);
        assert_eq!(load(&dir, &o.n), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
