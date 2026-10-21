//! The financier directory (HNK-30.T18, D-47): the financiers that chose to be listed, with what is
//! public about them anyway (a name, the contact card, the financier key) and a coarse public
//! mandate (amount range, longest tenor, whether buyers must be KYC'd). Suppliers' browsers match
//! an invoice against it locally and send a sealed offer to one financier; the detailed mandate
//! stays private on each node (N-15).
//!
//! The provider keeps the list on its own machine (`directory.json` next to `provider.key`) and
//! publishes it signed with the provider key: Ed25519 over `"JitsuinDirectory_v1\n"` ‖ the
//! canonical JSON of the directory without `sig` (keys sorted, no whitespace, as JTSM headers).
//! The web app checks that signature against the provider's public key before showing it.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::message::{self, canonical, hex, unhex};
use crate::relay::fingerprint;

pub const DOMAIN: &str = "JitsuinDirectory_v1\n";
/// The most financiers one directory lists.
pub const MAX: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mandate {
    pub min_zat: u64,
    pub max_zat: u64,
    pub max_tenor_days: u32,
    pub buyer_kyc: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    pub name: String,
    pub contact: String,
    pub financier_pk: String,
    pub mandate: Mandate,
    pub listed_at: u64,
}

/// The fingerprint inside a contact card (`jitsuin-contact-v1:` + base64url JSON).
fn card_fingerprint(card: &str) -> Option<String> {
    use base64::Engine;
    let body = card.strip_prefix("jitsuin-contact-v1:")?;
    let json: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .ok()?,
    )
    .ok()?;
    if json["role"] != "financier" {
        return None;
    }
    json["fingerprint"].as_str().map(String::from)
}

/// A listing, checked: the key is an Ed25519 key, the card names it, the mandate makes sense.
pub fn listing(
    name: &str,
    contact: &str,
    financier_pk: &str,
    mandate: Mandate,
    now: u64,
) -> Result<Listing, String> {
    let name: String = name.chars().filter(|c| !c.is_control()).take(60).collect();
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("give the financier a name".into());
    }
    let pk = unhex::<32>(&financier_pk.to_ascii_lowercase())
        .map_err(|_| "the financier key must be 64 hex characters")?;
    VerifyingKey::from_bytes(&pk).map_err(|_| "not a valid financier key")?;
    if card_fingerprint(contact).as_deref() != Some(fingerprint(&pk).as_str()) {
        return Err("this contact card does not belong to that financier key".into());
    }
    if mandate.max_zat == 0 || mandate.min_zat > mandate.max_zat {
        return Err("the amount range is not valid".into());
    }
    if !(1..=3650).contains(&mandate.max_tenor_days) {
        return Err("the longest tenor must be from 1 to 3650 days".into());
    }
    Ok(Listing {
        name,
        contact: contact.to_string(),
        financier_pk: hex(&pk),
        mandate,
        listed_at: now,
    })
}

/// Adds or replaces the listing for its financier key.
pub fn upsert(list: &mut Vec<Listing>, l: Listing) -> Result<(), String> {
    if let Some(i) = list.iter().position(|x| x.financier_pk == l.financier_pk) {
        list[i] = l;
    } else if list.len() >= MAX {
        return Err("the directory is full".into());
    } else {
        list.push(l);
    }
    Ok(())
}

/// The published directory, signed with the provider key.
pub fn signed(list: &[Listing], key: &SigningKey, issued_at: u64) -> Value {
    let mut d = json!({
        "v": 1,
        "kind": "jitsuin.directory",
        "issued_at": issued_at,
        "financiers": list,
        "signer": hex(&key.verifying_key().to_bytes()),
    });
    let sig = key.sign(format!("{DOMAIN}{}", canonical(&d)).as_bytes());
    d["sig"] = hex(&sig.to_bytes()).into();
    d
}

/// True when `d` is a directory signed by `expected` (hex).
pub fn verify(d: &Value, expected: &str) -> bool {
    if d["kind"] != "jitsuin.directory" || d["signer"].as_str() != Some(expected) {
        return false;
    }
    let (Ok(pk), Some(Ok(sig))) = (unhex::<32>(expected), d["sig"].as_str().map(unhex::<64>))
    else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let mut rest = d.clone();
    rest.as_object_mut().map(|m| m.remove("sig"));
    vk.verify(
        format!("{DOMAIN}{}", canonical(&rest)).as_bytes(),
        &Signature::from_bytes(&sig),
    )
    .is_ok()
}

/// The node provider's mailbox (jitsuinfi-frontend `src/lib/provider.ts`), where a financier's
/// node sends its public mandate; `PROVIDER_MAILBOX_PK` overrides it.
pub const PROVIDER_MAILBOX_PK: &str =
    "69c842daeffbe7c1f337158f223d9b6c98789a0ad72752da02fc1ad4080fd02e";

pub fn provider_mailbox() -> Result<[u8; 32], String> {
    unhex::<32>(
        &std::env::var("PROVIDER_MAILBOX_PK").unwrap_or_else(|_| PROVIDER_MAILBOX_PK.into()),
    )
}

/// The `financier.listing` a node sends the provider (HNK-30.T19): its name, contact card and
/// public mandate, signed with the financier key, so the provider lists exactly that key.
pub fn listing_message(
    key: &SigningKey,
    my_mailbox_pk: &[u8; 32],
    name: &str,
    contact: &str,
    mandate: &Mandate,
    now: u64,
) -> Result<Vec<u8>, String> {
    let to = provider_mailbox()?;
    let body = json!({ "name": name, "contact": contact, "mandate": mandate });
    let mut h = message::draft(
        "financier.listing",
        my_mailbox_pk,
        &to,
        None,
        body,
        &[],
        now,
    );
    message::sign(&mut h, key);
    message::encode(&h, &[])
}

/// A received `financier.listing`, checked: signed by the financier key it lists.
pub fn read_listing(h: &Value, now: u64) -> Result<Listing, String> {
    if h["type"] != "financier.listing" {
        return Err("not a financier listing".into());
    }
    let signer = h["signer"].as_str().ok_or("the listing is not signed")?;
    if !message::verify(h, Some(signer)) {
        return Err("the listing's signature does not hold".into());
    }
    let mandate: Mandate = serde_json::from_value(h["body"]["mandate"].clone())
        .map_err(|_| "the listing has no valid mandate")?;
    listing(
        h["body"]["name"].as_str().unwrap_or_default(),
        h["body"]["contact"].as_str().unwrap_or_default(),
        signer,
        mandate,
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::contact_card;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn mandate() -> Mandate {
        Mandate {
            min_zat: 10_000,
            max_zat: 50_000_000,
            max_tenor_days: 90,
            buyer_kyc: true,
        }
    }

    #[test]
    fn a_listing_needs_the_card_of_its_own_key() {
        let fin = key(3).verifying_key().to_bytes();
        let card = contact_card(&[7; 32], &fin);
        assert!(listing("Kurogane Capital", &card, &hex(&fin), mandate(), 1).is_ok());
        let other = contact_card(&[7; 32], &key(4).verifying_key().to_bytes());
        assert!(
            listing("Kurogane Capital", &other, &hex(&fin), mandate(), 1)
                .unwrap_err()
                .contains("does not belong")
        );
        let bad = Mandate {
            min_zat: 9,
            max_zat: 1,
            ..mandate()
        };
        assert!(listing("K", &card, &hex(&fin), bad, 1).is_err());
    }

    #[test]
    fn the_directory_verifies_and_any_change_breaks_it() {
        let p = key(9);
        let fin = key(3).verifying_key().to_bytes();
        let mut list = vec![];
        upsert(
            &mut list,
            listing(
                "Kurogane Capital",
                &contact_card(&[7; 32], &fin),
                &hex(&fin),
                mandate(),
                1,
            )
            .unwrap(),
        )
        .unwrap();
        let d = signed(&list, &p, 5);
        let pk = hex(&p.verifying_key().to_bytes());
        assert!(verify(&d, &pk));
        let mut changed = d.clone();
        changed["financiers"][0]["mandate"]["max_zat"] = 1.into();
        assert!(!verify(&changed, &pk));
        assert!(!verify(&d, &hex(&key(1).verifying_key().to_bytes())));
    }

    #[test]
    fn a_node_listing_reaches_the_provider_signed_by_its_own_key() {
        let fin = key(3);
        let card = contact_card(&[7; 32], &fin.verifying_key().to_bytes());
        let bytes =
            listing_message(&fin, &[7; 32], "Kurogane Capital", &card, &mandate(), 9).unwrap();
        let to = hex(&jitsuin_core::mailbox::mailbox_id(
            &provider_mailbox().unwrap(),
        ));
        let m = message::decode(&bytes, &to).unwrap();
        let l = read_listing(&m.header, 10).unwrap();
        assert_eq!(l.financier_pk, hex(&fin.verifying_key().to_bytes()));
        assert_eq!(l.mandate, mandate());
        let mut forged = m.header.clone();
        forged["body"]["mandate"]["max_zat"] = 1.into();
        assert!(read_listing(&forged, 10).is_err());
    }

    /// The same directory as jitsuinfi-frontend `tests/directory.test.ts` checks.
    #[test]
    fn vector_for_the_web_app() {
        let p = key(9);
        let fin = key(3).verifying_key().to_bytes();
        let l = listing(
            "Kurogane Capital",
            &contact_card(&[7; 32], &fin),
            &hex(&fin),
            mandate(),
            1_792_540_800,
        )
        .unwrap();
        let d = signed(&[l], &p, 1_792_540_900);
        let got = serde_json::to_string(&d).unwrap();
        if std::env::var_os("WRITE_VECTORS").is_some() {
            std::fs::write("tests/vectors/directory.json", &got).unwrap();
        }
        assert_eq!(got, include_str!("../tests/vectors/directory.json").trim());
    }
}
