//! The payment gate (HNK-26.T15, BL-D24-09, D-43): the node pays an advance only with a passkey
//! approval of that exact payment. The intent hash binds the deal (N), the amount and the
//! supplier's address, so an approval for one payment cannot be replayed for another, and the
//! deal API (HNK-26.T5+) has no way to call `Financier::pay_advance` around it.

use jitsuin_flow::financier::{Financier, Flow, State};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::console::{Console, PairError};

/// One payment the operator approves: shown in the console, hashed into the approval.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Intent {
    /// The deal's invoice fingerprint N (hex).
    pub n: String,
    pub amount_zat: u64,
    /// Shielded address that receives the advance.
    pub address: String,
}

impl Intent {
    pub fn hash(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(b"jitsuin-advance-approval-v1\n")
            .chain_update(self.n.as_bytes())
            .chain_update(b"\n")
            .chain_update(self.amount_zat.to_le_bytes())
            .chain_update(self.address.as_bytes())
            .finalize()
            .into()
    }

    /// The advance a flow in `Pay` would send.
    pub fn of(flow: &Flow) -> Intent {
        Intent {
            n: crate::message::hex(flow.nullifier()),
            amount_zat: flow.deal().advance_zat,
            address: flow.deal().supplier_address.clone(),
        }
    }
}

#[derive(Debug)]
pub enum PayError {
    NotApproved(PairError),
    Flow(jitsuin_flow::Error),
}

impl std::fmt::Display for PayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayError::NotApproved(e) => f.write_str(e.message()),
            PayError::Flow(e) => write!(f, "{e}"),
        }
    }
}

/// Pays the advance of `flow` only when `approval` approves exactly this payment; the approval is
/// used up first, so a failed payment needs a new approval.
#[allow(dead_code)] // called by the deal API (HNK-26.T5+), the only path to an advance
pub fn advance(
    console: &Console,
    approval: &str,
    financier: &Financier,
    flow: &mut Flow,
    date: u32,
) -> Result<State, PayError> {
    console
        .take_approval(approval, &Intent::of(flow).hash())
        .map_err(PayError::NotApproved)?;
    financier
        .pay_advance(flow, date)
        .cloned()
        .map_err(PayError::Flow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_intent_hash_binds_deal_amount_and_address() {
        let i = Intent {
            n: "ab".repeat(32),
            amount_zat: 1_000,
            address: "utest1a".into(),
        };
        let h = i.hash();
        assert_ne!(
            h,
            Intent {
                amount_zat: 1_001,
                ..i.clone()
            }
            .hash()
        );
        assert_ne!(
            h,
            Intent {
                address: "utest1b".into(),
                ..i.clone()
            }
            .hash()
        );
        assert_ne!(
            h,
            Intent {
                n: "cd".repeat(32),
                ..i.clone()
            }
            .hash()
        );
        assert_eq!(h, i.clone().hash());
    }
}
