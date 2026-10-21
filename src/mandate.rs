//! The financier's private mandate (HNK-30.T11, N-15): structured rules kept only on this node
//! (`private-mandate.json`), matched locally against each sealed `deal.offer` once the node has
//! opened it. The console shows which rule an offer fits or breaks; the financier still accepts or
//! declines (`deal.decline`, HNK-26.T6) by hand. No rule leaves the node: the public directory
//! carries only the coarse public mandate (D-47).
//!
//! Rules (each optional): largest face value, longest tenor (days from today to the due date),
//! smallest discount (the share of the face value the financier keeps), a buyer history of at
//! least `k` anchored invoices, and a buyer identity in the KYC registry (HNK-26.T7). The last two
//! need a `history.chain` for the same N in the mailbox; until one arrives they are "waiting".

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const FILE: &str = "private-mandate.json";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateMandate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_face_zat: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tenor_days: Option<u32>,
    /// In basis points: 250 = the advance is at most 97.5 % of the face value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_discount_bps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_buyer_history: Option<u32>,
    #[serde(default)]
    pub buyer_kyc: bool,
}

impl PrivateMandate {
    pub fn load(dir: &Path) -> Self {
        std::fs::read(dir.join(FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let tmp = dir.join(format!("{FILE}.tmp"));
        std::fs::write(&tmp, serde_json::to_vec(self).expect("json"))?;
        std::fs::rename(tmp, dir.join(FILE))
    }

    pub fn check(&self) -> Result<(), &'static str> {
        if self.max_face_zat == Some(0) {
            return Err("the largest invoice must be more than zero");
        }
        if self
            .max_tenor_days
            .is_some_and(|d| !(1..=3650).contains(&d))
        {
            return Err("the longest tenor must be from 1 to 3650 days");
        }
        if self.min_discount_bps.is_some_and(|b| b >= 10_000) {
            return Err("the smallest discount must be under 100 %");
        }
        if self.min_buyer_history.is_some_and(|k| k > 64) {
            return Err("a buyer history holds at most 64 invoices");
        }
        Ok(())
    }
}

/// What the mailbox says about the buyer of one N: the longest history chain it holds and whether
/// any of them comes from a registered identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Buyer {
    pub history: Option<u32>,
    pub registered: bool,
}

/// One rule's verdict: `Some(true)` fits, `Some(false)` breaks, `None` waiting for the buyer.
fn rule(name: &str, ok: Option<bool>, detail: String) -> Value {
    json!({ "rule": name, "ok": ok, "detail": detail })
}

/// Matches an offer (as `offer::summary` shows it) against the mandate. `today` is days since the
/// epoch. Returns `{verdict: "fits" | "breaks" | "waiting" | "none", rules: [...]}`.
pub fn verdict(m: &PrivateMandate, offer: &Value, buyer: &Buyer, today: u32) -> Value {
    let face = offer["amount_zat"].as_u64().unwrap_or(0);
    let advance = offer["advance_zat"].as_u64().unwrap_or(0);
    let due = offer["due_date"].as_u64().unwrap_or(0) as i64;
    let mut rules = vec![];
    if let Some(max) = m.max_face_zat {
        rules.push(rule(
            "largest invoice",
            Some(face <= max),
            format!("face {face} zat, at most {max}"),
        ));
    }
    if let Some(max) = m.max_tenor_days {
        let days = due - today as i64;
        rules.push(rule(
            "longest tenor",
            Some(days >= 0 && days <= max as i64),
            format!("{days} days to the due date, at most {max}"),
        ));
    }
    if let Some(min) = m.min_discount_bps {
        let bps = if face == 0 {
            0
        } else {
            (face.saturating_sub(advance) as u128 * 10_000 / face as u128) as u32
        };
        rules.push(rule(
            "smallest discount",
            Some(advance <= face && bps >= min),
            format!(
                "{}.{:02} % asked, at least {}.{:02} %",
                bps / 100,
                bps % 100,
                min / 100,
                min % 100
            ),
        ));
    }
    if let Some(k) = m.min_buyer_history {
        rules.push(match buyer.history {
            None => rule(
                "buyer history",
                None,
                format!("waiting for the buyer's history (at least {k})"),
            ),
            Some(h) => rule(
                "buyer history",
                Some(h >= k),
                format!("{h} anchored invoices, at least {k}"),
            ),
        });
    }
    if m.buyer_kyc {
        rules.push(match (buyer.history, buyer.registered) {
            (_, true) => rule("buyer KYC", Some(true), "identity in your KYC list".into()),
            (None, false) => rule(
                "buyer KYC",
                None,
                "waiting for the buyer's history with its identity key".into(),
            ),
            (Some(_), false) => rule(
                "buyer KYC",
                Some(false),
                "the buyer's identity is not in your KYC list".into(),
            ),
        });
    }
    let v = if rules.is_empty() {
        "none"
    } else if rules.iter().any(|r| r["ok"] == false) {
        "breaks"
    } else if rules.iter().any(|r| r["ok"].is_null()) {
        "waiting"
    } else {
        "fits"
    };
    json!({ "verdict": v, "rules": rules })
}

/// The reason to send with a decline, from the rules an offer breaks (no number from the private
/// mandate is disclosed: only which kind of rule).
pub fn decline_reason(v: &Value) -> String {
    let broken: Vec<&str> = v["rules"]
        .as_array()
        .map(|r| {
            r.iter()
                .filter(|x| x["ok"] == false)
                .filter_map(|x| x["rule"].as_str())
                .collect()
        })
        .unwrap_or_default();
    if broken.is_empty() {
        "The financier declined this offer.".into()
    } else {
        format!("Outside this financier's terms: {}.", broken.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(face: u64, advance: u64, due: u64) -> Value {
        json!({ "amount_zat": face, "advance_zat": advance, "due_date": due })
    }

    #[test]
    fn an_offer_fits_breaks_or_waits_for_the_buyer() {
        let m = PrivateMandate {
            max_face_zat: Some(1_000_000),
            max_tenor_days: Some(90),
            min_discount_bps: Some(200),
            min_buyer_history: Some(2),
            buyer_kyc: true,
        };
        assert!(m.check().is_ok());
        let known = Buyer {
            history: Some(3),
            registered: true,
        };
        let fits = verdict(&m, &offer(1_000_000, 970_000, 160), &known, 100);
        assert_eq!(fits["verdict"], "fits", "{fits}");
        let waits = verdict(&m, &offer(1_000_000, 970_000, 160), &Buyer::default(), 100);
        assert_eq!(waits["verdict"], "waiting");
        let breaks = verdict(&m, &offer(1_000_000, 990_000, 300), &known, 100);
        assert_eq!(breaks["verdict"], "breaks");
        let reason = decline_reason(&breaks);
        assert_eq!(
            reason,
            "Outside this financier's terms: longest tenor, smallest discount."
        );
        assert!(!reason.contains("90") && !reason.contains("200"));
        let unknown = Buyer {
            history: Some(5),
            registered: false,
        };
        assert_eq!(
            verdict(&m, &offer(10, 9, 101), &unknown, 100)["verdict"],
            "breaks"
        );
    }

    #[test]
    fn no_rule_is_no_verdict_and_bad_rules_are_refused() {
        let none = verdict(
            &PrivateMandate::default(),
            &offer(1, 1, 1),
            &Buyer::default(),
            0,
        );
        assert_eq!(none["verdict"], "none");
        assert!(PrivateMandate {
            min_discount_bps: Some(10_000),
            ..Default::default()
        }
        .check()
        .is_err());
        assert!(PrivateMandate {
            max_tenor_days: Some(0),
            ..Default::default()
        }
        .check()
        .is_err());
    }
}
