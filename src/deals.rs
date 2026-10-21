//! The deal after "Accept" (HNK-26.T16, HNK-23.T8, SEQ-03 parts 2–5): the node keeps one
//! `jitsuin_flow::financier::Flow` per invoice (`deals/<N>.flow`, format `JTSF`, HNK-26.T10) and
//! moves it with what arrives in its mailbox and what the board shows:
//!
//! 1. `Check`: the board has no entry for N (lookup on the node's latest board scan).
//! 2. `AwaitSupplierSignature`: the supplier's `deal.entry` (it signed the entry for our
//!    commitment with the salt from `deal.commitment_opening`).
//! 3. `Register`: the node posts the entry to the board (a 10 000 zat self-paid memo).
//! 4. `AwaitConfirmation`: the entry is mined, confirmed and still the first valid one.
//! 5. `AwaitAssignment`: the node sends the assignment letter and its PDF (`deal.letter`) to the
//!    supplier and the buyer, then waits for their seals (`deal.seal` index 0 and 1).
//! 6. `Pay`: only the operator's passkey approval of this exact advance moves money (`pay.rs`).
//! 7. `AwaitAdvanceConfirmation` → `Done`; the supplier gets `deal.advance` with the txid.
//!
//! The letter's PDF is generated here from the deal's own fields, so its SHA-256 (the letter's
//! `terms_hash`) can be recomputed by anyone holding the PDF.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use jitsuin_core::{commitment_opening, document_hash, Assignment, BoardEntry, Invoice, Seal};
use jitsuin_flow::financier::{Deal, Flow, State};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::message::{self, hex, unhex, File};
use crate::offer::Accepted;

fn flow_path(dir: &Path, n: &str) -> PathBuf {
    dir.join(format!("{n}.flow"))
}

fn meta_path(dir: &Path, n: &str) -> PathBuf {
    dir.join(format!("{n}.meta.json"))
}

pub fn pdf_path(dir: &Path, n: &str) -> PathBuf {
    dir.join(format!("{n}.letter.pdf"))
}

/// What the node did besides the flow: messages sent once.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    #[serde(default)]
    pub letter_sent: bool,
    #[serde(default)]
    pub advance_sent: bool,
    /// HNK-26.T11–T12: the repayment as the wallet sees it, and the `settled` entry once posted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repayment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paid_zat: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_txid: Option<String>,
    /// The supplier's and the buyer's seals (base64url), kept for the bundle.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seals: Vec<String>,
    #[serde(default)]
    pub bundle_sent: bool,
    /// The last thing that went wrong, shown in the console.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

pub fn load_meta(dir: &Path, n: &str) -> Meta {
    std::fs::read(meta_path(dir, n))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn save_meta(dir: &Path, n: &str, m: &Meta) -> std::io::Result<()> {
    write_atomic(&meta_path(dir, n), &serde_json::to_vec(m).expect("json"))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, path)
}

pub fn load_flow(dir: &Path, n: &str) -> Option<Flow> {
    Flow::from_bytes(&std::fs::read(flow_path(dir, n)).ok()?).ok()
}

pub fn save_flow(dir: &Path, n: &str, f: &Flow) -> Result<(), String> {
    let bytes = f.to_bytes().map_err(|e| e.to_string())?;
    write_atomic(&flow_path(dir, n), &bytes).map_err(|e| e.to_string())
}

/// The N of every deal with a flow.
pub fn list(dir: &Path) -> Vec<String> {
    let mut ns: Vec<String> = std::fs::read_dir(dir)
        .map(|d| {
            d.filter_map(|e| {
                e.ok()?
                    .file_name()
                    .to_str()?
                    .strip_suffix(".flow")
                    .map(String::from)
            })
            .collect()
        })
        .unwrap_or_default();
    ns.sort();
    ns
}

fn day(days: u32) -> String {
    // civil date from days since 1970-01-01 (Howard Hinnant's algorithm)
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn zec(zat: u64) -> String {
    format!("{}.{:08} ZEC", zat / 100_000_000, zat % 100_000_000)
}

/// A one-page PDF (Helvetica, ASCII) with `lines`; byte-for-byte the same for the same lines.
pub fn pdf(lines: &[String]) -> Vec<u8> {
    let esc = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii() && !c.is_ascii_control())
            .flat_map(|c| match c {
                '(' | ')' | '\\' => vec!['\\', c],
                c => vec![c],
            })
            .collect()
    };
    let mut content = String::from("BT /F1 11 Tf 56 780 Td 15 TL\n");
    for (i, l) in lines.iter().enumerate() {
        if i == 0 {
            content += &format!("/F1 16 Tf ({}) Tj T* T* /F1 11 Tf\n", esc(l));
        } else {
            content += &format!("({}) Tj T*\n", esc(l));
        }
    }
    content += "ET\n";
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_string(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
        format!("<< /Length {} >>\nstream\n{content}endstream", content.len()),
    ];
    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offsets = vec![];
    for (i, o) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// The assignment letter's PDF: the terms the seals agree to, in words.
pub fn letter_pdf(
    inv: &Invoice,
    n: &str,
    financier_pk: &[u8; 32],
    address: &str,
    name: &str,
) -> Vec<u8> {
    let wrap = |label: &str, v: &str| -> Vec<String> {
        let mut out = vec![];
        let mut rest = v;
        let mut first = true;
        while !rest.is_empty() || first {
            let take = rest.len().min(72);
            out.push(format!(
                "{}{}",
                if first { label } else { "    " },
                &rest[..take]
            ));
            rest = &rest[take..];
            first = false;
        }
        out
    };
    let mut l = vec![
        "Notice of assignment of a receivable".to_string(),
        format!("Invoice {} (JitsuinFi, Zcash testnet)", inv.invoice_id),
        String::new(),
        format!(
            "The supplier assigns this invoice to the financier {}.",
            if name.is_empty() { "named below" } else { name }
        ),
        "From the moment all three seals are on this letter, the buyer pays the financier,".into(),
        "at the address below, and nobody else.".into(),
        String::new(),
        format!("Amount due: {}", zec(inv.amount_zat)),
        format!("Due date:   {}", day(inv.due_date)),
    ];
    l.extend(wrap("Fingerprint N: ", n));
    l.extend(wrap("Financier key: ", &hex(financier_pk)));
    l.extend(wrap("Pay to:        ", address));
    l.extend([
        String::new(),
        "Seals, in order: supplier, buyer, financier. The financier seals last, in the same".into(),
        "shielded transaction that pays the advance (Sign-to-Pay).".into(),
    ]);
    pdf(&l)
}

/// Builds the deal and its flow from the accepted terms; the letter's PDF goes to `dir`.
pub fn start(
    dir: &Path,
    a: &Accepted,
    key: &SigningKey,
    address: &str,
    name: &str,
) -> Result<Flow, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&a.invoice)
        .map_err(|_| "the saved invoice is not base64url")?;
    let invoice = Invoice::from_canonical_bytes(&bytes).map_err(|e| format!("{e:?}"))?;
    let financier_pk = key.verifying_key().to_bytes();
    let pdf = letter_pdf(&invoice, &a.n, &financier_pk, address, name);
    let assignment = Assignment::for_invoice(&invoice, financier_pk, address, document_hash(&pdf))
        .map_err(|e| e.to_string())?;
    let (_, commitment) = commitment_opening(key, &unhex::<32>(&a.n)?);
    let flow = Flow::new(Deal {
        invoice,
        assignment,
        financier_commitment: commitment,
        supplier_address: a.supplier_address.clone(),
        advance_zat: a.advance_zat,
        min_confirmations: a.min_confirmations,
        history_tag: None,
        discount_bucket: a.discount,
        tenor_bucket: a.tenor,
    })
    .map_err(|e| e.to_string())?;
    write_atomic(&pdf_path(dir, &a.n), &pdf).map_err(|e| e.to_string())?;
    save_flow(dir, &a.n, &flow)?;
    Ok(flow)
}

/// The supplier's signed board entry from a `deal.entry` for N.
pub fn read_entry(h: &Value, n: &str) -> Result<BoardEntry, String> {
    if h["type"] != "deal.entry" || h["n"].as_str() != Some(n) {
        return Err("not the board entry of this deal".into());
    }
    let memo = h["body"]["memo"]
        .as_str()
        .and_then(|m| URL_SAFE_NO_PAD.decode(m).ok())
        .ok_or("the entry is not base64url")?;
    BoardEntry::from_memo_bytes(&memo).map_err(|e| format!("the entry does not decode: {e:?}"))
}

/// A `deal.seal` for N: its index (0 supplier, 1 buyer) and the seal.
pub fn read_seal(h: &Value, n: &str) -> Result<(u64, Seal), String> {
    if h["type"] != "deal.seal" || h["n"].as_str() != Some(n) {
        return Err("not a seal of this deal".into());
    }
    let index = h["body"]["index"].as_u64().ok_or("the seal has no index")?;
    let seal = h["body"]["seal"]
        .as_str()
        .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
        .ok_or("the seal is not base64url")
        .and_then(|b| Seal::from_bytes(&b).map_err(|_| "not a seal"))?;
    Ok((index, seal))
}

/// `deal.letter` to `to`: the letter (JTSA) and its PDF.
pub fn letter_message(
    key: &SigningKey,
    me: &[u8; 32],
    to: &[u8; 32],
    flow: &Flow,
    pdf: &[u8],
    now: u64,
) -> Result<Vec<u8>, String> {
    let letter = flow
        .deal()
        .assignment
        .to_canonical_bytes()
        .map_err(|e| e.to_string())?;
    let files = [File {
        name: format!("assignment-{}.pdf", flow.deal().invoice.invoice_id),
        bytes: pdf.to_vec(),
    }];
    let n = hex(flow.nullifier());
    let mut h = message::draft(
        "deal.letter",
        me,
        to,
        Some(&n),
        json!({ "letter": URL_SAFE_NO_PAD.encode(letter) }),
        &files,
        now,
    );
    message::sign(&mut h, key);
    message::encode(&h, &files)
}

/// `deal.advance` to the supplier: the advance's txid.
pub fn advance_message(
    key: &SigningKey,
    me: &[u8; 32],
    to: &[u8; 32],
    flow: &Flow,
    txid: &str,
    now: u64,
) -> Result<Vec<u8>, String> {
    let n = hex(flow.nullifier());
    let mut h = message::draft(
        "deal.advance",
        me,
        to,
        Some(&n),
        json!({ "txid": txid, "advance_zat": flow.deal().advance_zat }),
        &[],
        now,
    );
    message::sign(&mut h, key);
    message::encode(&h, &[])
}

/// HNK-26.T18: the verification bundle (JTSB) of a settled deal: the invoice and the buyer's
/// signature, the letter with all three seals (the financier's is recomputed: Ed25519 is
/// deterministic, so it is the seal that travelled with the advance), and the settlement document.
pub fn bundle(
    flow: &Flow,
    buyer_signature: &str,
    seals: &[String],
    key: &SigningKey,
) -> Result<Vec<u8>, String> {
    let mut chain: Vec<Seal> = seals
        .iter()
        .map(|s| {
            URL_SAFE_NO_PAD
                .decode(s)
                .ok()
                .and_then(|b| Seal::from_bytes(&b).ok())
                .ok_or_else(|| "a kept seal does not decode".to_string())
        })
        .collect::<Result<_, _>>()?;
    let a = &flow.deal().assignment;
    chain.push(a.seal_next(key, &chain).map_err(|e| e.to_string())?);
    let b = jitsuin_core::Bundle {
        invoice: flow.deal().invoice.clone(),
        buyer_signature: unhex::<64>(buyer_signature)?,
        assignment: Some(a.clone()),
        assignment_seals: chain,
        settlement: Some(jitsuin_core::SettlementDoc::for_assignment(a)),
    };
    b.verify()
        .map_err(|e| format!("the bundle does not verify: {e}"))?;
    b.to_bytes().map_err(|e| e.to_string())
}

/// `deal.bundle` to `to`.
pub fn bundle_message(
    key: &SigningKey,
    me: &[u8; 32],
    to: &[u8; 32],
    n: &str,
    bundle: &[u8],
    now: u64,
) -> Result<Vec<u8>, String> {
    let mut h = message::draft(
        "deal.bundle",
        me,
        to,
        Some(n),
        json!({ "bundle": URL_SAFE_NO_PAD.encode(bundle) }),
        &[],
        now,
    );
    message::sign(&mut h, key);
    message::encode(&h, &[])
}

/// What the console shows of a deal's state.
pub fn view(flow: &Flow) -> Value {
    let s = flow.state();
    let mut v = json!({ "state": s.name() });
    match s {
        State::AwaitConfirmation { entry_txid } => v["entry_txid"] = entry_txid.clone().into(),
        State::AwaitAssignment { entry } | State::Pay { entry, .. } => {
            v["entry_txid"] = entry.txid.clone().into()
        }
        State::AwaitAdvanceConfirmation {
            entry,
            advance_txid,
            ..
        }
        | State::Done {
            entry,
            advance_txid,
        } => {
            v["entry_txid"] = entry.txid.clone().into();
            v["advance_txid"] = advance_txid.clone().into();
        }
        State::Stopped(stop) => v["stopped"] = format!("{stop:?}").into(),
        _ => {}
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitsuin_core::invoice::sign_invoice;

    #[test]
    fn the_letter_pdf_is_stable_and_well_formed() {
        let p = pdf(&["Title (a)".into(), "line \\ two".into()]);
        assert!(p.starts_with(b"%PDF-1.4") && p.ends_with(b"%%EOF\n"));
        assert_eq!(p, pdf(&["Title (a)".into(), "line \\ two".into()]));
        let s = String::from_utf8_lossy(&p);
        assert!(s.contains("(Title \\(a\\)) Tj") && s.contains("(line \\\\ two) Tj"));
        // the xref offset points at the xref table
        let start: usize = s
            .rsplit("startxref\n")
            .next()
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(s[start..].starts_with("xref"));
        assert_eq!(day(0), "1970-01-01");
        assert_eq!(day(20_747), "2026-10-21");
    }

    #[test]
    fn a_deal_starts_from_accepted_terms_and_reloads() {
        let supplier = SigningKey::from_bytes(&[1; 32]);
        let buyer = SigningKey::from_bytes(&[2; 32]);
        let fin = SigningKey::from_bytes(&[3; 32]);
        let inv = Invoice {
            invoice_id: "TES-INV-9".into(),
            supplier_ephemeral_pk: supplier.verifying_key().to_bytes(),
            buyer_pk: buyer.verifying_key().to_bytes(),
            amount_zat: 1_000_000,
            issue_date: 20_740,
            due_date: 20_800,
            terms_hash: [5; 32],
        };
        let sig = sign_invoice(&buyer, &inv).unwrap();
        let n = hex(&jitsuin_core::nullifier(&inv).unwrap());
        let a = Accepted {
            n: n.clone(),
            invoice: URL_SAFE_NO_PAD.encode(inv.to_canonical_bytes().unwrap()),
            buyer_signature: hex(&sig.to_bytes()),
            advance_zat: 950_000,
            min_confirmations: 1,
            supplier_address: "utest1supplier".into(),
            supplier_mailbox_pk: hex(&[7; 32]),
            buyer_mailbox_pk: None,
            discount: 0,
            tenor: 0,
            accepted_at: 1,
        };
        let dir = std::env::temp_dir().join(format!("jitsuin-deals-{}", message::random_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = start(&dir, &a, &fin, "utest1financier", "Kurogane").unwrap();
        assert_eq!(f.state(), &State::Check);
        assert_eq!(list(&dir), vec![n.clone()]);
        let back = load_flow(&dir, &n).unwrap();
        assert_eq!(back.nullifier(), f.nullifier());
        let pdf = std::fs::read(pdf_path(&dir, &n)).unwrap();
        assert_eq!(f.deal().assignment.terms_hash, document_hash(&pdf));
        let bytes = letter_message(&fin, &[8; 32], &[7; 32], &f, &pdf, 5).unwrap();
        let to = hex(&jitsuin_core::mailbox::mailbox_id(&[7; 32]));
        let m = message::decode(&bytes, &to).unwrap();
        assert_eq!(m.header["type"], "deal.letter");
        assert!(message::verify(
            &m.header,
            Some(&hex(&fin.verifying_key().to_bytes()))
        ));

        // HNK-26.T18: the supplier and the buyer seal, the bundle adds the financier's seal
        let letter = &f.deal().assignment;
        let s0 = letter.seal_next(&supplier, &[]).unwrap();
        let s1 = letter.seal_next(&buyer, std::slice::from_ref(&s0)).unwrap();
        let kept: Vec<String> = [s0, s1]
            .iter()
            .map(|s| URL_SAFE_NO_PAD.encode(s.to_bytes()))
            .collect();
        let b = bundle(&f, &a.buyer_signature, &kept, &fin).unwrap();
        let back = jitsuin_core::Bundle::from_bytes(&b).unwrap();
        assert_eq!(back.assignment_seals.len(), 3);
        assert!(bundle(&f, &a.buyer_signature, &kept[..1], &fin).is_err());
    }

    #[test]
    fn entries_and_seals_are_read_only_for_their_own_deal() {
        let h = json!({ "type": "deal.entry", "n": "aa", "body": { "memo": "!!" } });
        assert!(read_entry(&h, "aa").is_err());
        assert!(read_entry(&h, "bb")
            .unwrap_err()
            .contains("not the board entry"));
        let s = json!({ "type": "deal.seal", "n": "aa", "body": { "seal": "AAAA", "index": 0 } });
        assert!(read_seal(&s, "aa").unwrap_err().contains("not a seal"));
        assert!(read_seal(&s, "bb").is_err());
    }
}
