//! The fund ledger on the manager's node (HNK-29.T1–T2, HNK-30.T23, D-49): members hold units, not
//! balances. A deposit buys units at the period's NAV and its receipt carries a fresh withdraw
//! token (the member has no signing key, only a mailbox); the leaf id is the token's hash
//! (`jitsuin_core::units`). A member asks to withdraw by opening the token in a sealed
//! `fund.withdraw`; requests wait for the end of the period. Closing a period values the fund
//! on its books (cash plus receivables, as members compute it with `jitsuin fund`), pays the
//! queue from the books' cash only (pro rata when cash is short, nothing while the fund is below
//! par), signs the new unit tree's root into `JTLR`, and sends every member their path with the
//! books.
//!
//! **Assets are the members' money (user decision 2026-10-25).** The node's wallet also holds
//! the financier's own money, so its balance is not the fund's: a close valued on the wallet
//! priced period 1 of the production E2E at 5998.2 zat per unit. The fund's books are the
//! deposits recorded here and their flows, replayed from the chain by
//! `jitsuin_flow::fund::fund_books`: an advance is the fund's when the books' cash covered it in
//! full when it was paid, its repayments come back to the books, payouts leave them. Network fees
//! are paid by the wallet, not the books. Members get the books' txids with their path and read
//! the values from the chain themselves; the solvency check also asks that the wallet hold at
//! least the books' cash (it does not show that the cash is set apart from the financier's).
//!
//! Paying is money leaving the node, so the close runs only with a passkey approval of that
//! exact plan (D-43, as `pay::advance`).
//!
//! Stored as `fund.json` in the node's volume.

use std::path::Path;

use ed25519_dalek::SigningKey;
use jitsuin_core::units::{self, UnitTree};
use jitsuin_flow::fund::{FundBooks, FundView, ReceivableStatus};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::message::{self, hex, unhex};

pub const FILE: &str = "fund.json";
/// Kept back from cash at a close for the fees and the root self-send.
pub const RESERVE_ZAT: u64 = 100_000;
/// Share of an overdue receivable written off when valuing the fund, in percent.
pub const OVERDUE_HAIRCUT_PCT: u64 = 50;

/// The price of units: `assets_zat / units` zatoshi per unit. Par is 1 zat per unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nav {
    pub assets_zat: u64,
    pub units: u64,
}

impl Nav {
    pub const PAR: Nav = Nav {
        assets_zat: 1,
        units: 1,
    };

    /// Units bought for `zat`, rounded down.
    pub fn units_for(&self, zat: u64) -> u64 {
        (zat as u128 * self.units as u128 / self.assets_zat.max(1) as u128) as u64
    }

    /// Zatoshi paid for `units`, rounded down.
    pub fn value_of(&self, units: u64) -> u64 {
        (units as u128 * self.assets_zat as u128 / self.units.max(1) as u128) as u64
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leaf {
    /// `units::leaf_id(token)`, hex.
    pub id: String,
    pub units: u64,
    /// Where the fund sends this leaf's receipts and paths.
    pub mailbox_pk: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub leaf: String,
    pub units: u64,
    pub address: String,
    pub relay_id: String,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Close {
    pub period: u32,
    pub root: String,
    pub total_units: u64,
    pub nav: Nav,
    pub paid_zat: u64,
    pub payout_txid: Option<String>,
    pub root_txid: String,
    pub held: bool,
    /// Valued on the fund's books (2026-10-25); false for a close valued on the whole wallet.
    #[serde(default)]
    pub books: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    /// The open period; deposits and requests made now belong to it.
    pub period: u32,
    /// The price deposits pay in this period: the NAV of the last close.
    pub nav: Nav,
    pub leaves: Vec<Leaf>,
    /// Deposit txids already recorded.
    pub deposits: Vec<String>,
    pub queue: Vec<Request>,
    pub closes: Vec<Close>,
    /// The first period valued on the books (2026-10-25). None in a ledger written before: its
    /// last close priced the units on the whole wallet, so `nav` is repriced from the books
    /// (`reprice`) before the next deposit buys at it.
    #[serde(default)]
    pub books_since: Option<u32>,
}

impl Default for Ledger {
    fn default() -> Self {
        Ledger {
            period: 1,
            nav: Nav::PAR,
            leaves: vec![],
            deposits: vec![],
            queue: vec![],
            closes: vec![],
            books_since: Some(1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Payout {
    pub leaf: String,
    pub units: u64,
    pub amount_zat: u64,
    pub address: String,
}

/// What a close will do; the passkey approves its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub period: u32,
    pub nav: Nav,
    /// The books' cash: what withdrawals are paid from.
    pub cash_zat: u64,
    /// The whole wallet's balance (shared with the financier's own money); it must cover the
    /// payouts plus the reserve.
    pub wallet_zat: u64,
    pub payouts: Vec<Payout>,
    /// Below par: no request is paid this period.
    pub held: bool,
    /// Cash did not cover the queue: every request was paid the same share.
    pub short: bool,
    /// The ledger the plan was made from; a close refuses a ledger that changed since.
    pub ledger: String,
    /// HNK-30.T22: what the fund holds, in aggregate, sent to members with their paths.
    pub portfolio: Option<Portfolio>,
}

/// The fund's receivables in aggregate (HNK-30.T22): counts, sums and how far the open ones are
/// from their due dates; no N, no party. The same numbers a member computes with the viewing key
/// (`jitsuin fund`); here they arrive with the period's path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Portfolio {
    pub cash_zat: u64,
    pub open: u32,
    pub open_zat: u64,
    pub overdue: u32,
    pub overdue_zat: u64,
    pub repaid: u32,
    /// Open receivables due within 30 days, 31 – 90 days, later.
    pub due_within: [u32; 3],
}

pub fn portfolio(view: &FundView, today: u32) -> Portfolio {
    let mut p = Portfolio {
        cash_zat: view.cash_zat,
        open: 0,
        open_zat: 0,
        overdue: 0,
        overdue_zat: 0,
        repaid: 0,
        due_within: [0; 3],
    };
    for r in &view.receivables {
        match r.status {
            ReceivableStatus::Open => {
                p.open += 1;
                p.open_zat += r.outstanding_zat();
                let days = r.due_date.saturating_sub(today);
                p.due_within[if days <= 30 {
                    0
                } else if days <= 90 {
                    1
                } else {
                    2
                }] += 1;
            }
            ReceivableStatus::Overdue => {
                p.overdue += 1;
                p.overdue_zat += r.outstanding_zat();
            }
            ReceivableStatus::Repaid => p.repaid += 1,
        }
    }
    p
}

impl Plan {
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new()
            .chain_update(b"jitsuin-fund-close-v1\n")
            .chain_update(self.period.to_le_bytes())
            .chain_update(self.nav.assets_zat.to_le_bytes())
            .chain_update(self.nav.units.to_le_bytes());
        for p in &self.payouts {
            h = h
                .chain_update(p.leaf.as_bytes())
                .chain_update(p.units.to_le_bytes())
                .chain_update(p.amount_zat.to_le_bytes())
                .chain_update(p.address.as_bytes())
                .chain_update(b"\n");
        }
        h.chain_update(self.ledger.as_bytes()).finalize().into()
    }

    pub fn paid_zat(&self) -> u64 {
        self.payouts.iter().map(|p| p.amount_zat).sum()
    }
}

/// After a close: what each paid member is told, with the token for what is left of their leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paid {
    pub payout: Payout,
    pub mailbox_pk: String,
    pub next: Option<([u8; 32], Leaf)>,
}

fn valid_address(a: &str) -> bool {
    (10..=512).contains(&a.len()) && a.bytes().all(|b| b.is_ascii_alphanumeric())
}

impl Ledger {
    pub fn load(dir: &Path) -> std::io::Result<Self> {
        match std::fs::read(dir.join(FILE)) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Ledger::default()),
            Err(e) => Err(e),
        }
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let tmp = dir.join(format!("{FILE}.tmp"));
        std::fs::write(&tmp, serde_json::to_vec(self).expect("json"))?;
        std::fs::rename(tmp, dir.join(FILE))
    }

    pub fn total_units(&self) -> u64 {
        self.leaves.iter().map(|l| l.units).sum()
    }

    /// A digest of the whole ledger, so a plan only applies to the ledger it was made from.
    pub fn digest(&self) -> String {
        hex(&Sha256::digest(serde_json::to_vec(self).expect("json")))
    }

    pub fn tree(&self) -> UnitTree {
        let leaves: Vec<_> = self
            .leaves
            .iter()
            .filter_map(|l| Some((unhex::<32>(&l.id).ok()?, l.units)))
            .collect();
        UnitTree::build(&leaves).expect("leaf ids are distinct and units fit")
    }

    /// Records a deposit seen in the wallet: a new leaf at this period's NAV.
    pub fn deposit(
        &mut self,
        mailbox_pk: &[u8; 32],
        amount_zat: u64,
        txid: &str,
        token: &[u8; 32],
    ) -> Result<u64, String> {
        if self.deposits.iter().any(|t| t == txid) {
            return Err("this deposit is recorded already".into());
        }
        let u = self.nav.units_for(amount_zat);
        if u == 0 {
            return Err("the deposit is too small to buy a unit".into());
        }
        self.total_units()
            .checked_add(u)
            .ok_or("the fund cannot hold more units")?;
        self.leaves.push(Leaf {
            id: hex(&units::leaf_id(token)),
            units: u,
            mailbox_pk: hex(mailbox_pk),
        });
        self.deposits.push(txid.to_string());
        Ok(u)
    }

    /// Queues a request opened with `token`; `units` None is everything. A new request for the
    /// same leaf replaces the old one.
    pub fn withdraw(
        &mut self,
        token: &[u8; 32],
        units: Option<u64>,
        address: &str,
        relay_id: &str,
        at: u64,
    ) -> Result<u64, String> {
        let id = hex(&units::leaf_id(token));
        let leaf = self
            .leaves
            .iter()
            .find(|l| l.id == id)
            .ok_or("this withdraw token does not open any units here (used already?)")?;
        let u = units.unwrap_or(leaf.units);
        if u == 0 || u > leaf.units {
            return Err(format!("this token holds {} units", leaf.units));
        }
        if !valid_address(address) {
            return Err("the payout address is not a Zcash address".into());
        }
        self.queue.retain(|r| r.leaf != id);
        self.queue.push(Request {
            leaf: id,
            units: u,
            address: address.to_string(),
            relay_id: relay_id.to_string(),
            at,
        });
        Ok(u)
    }

    /// The fund's own transactions for `jitsuin_flow::fund::fund_books`: every recorded deposit
    /// and every close's payout.
    pub fn books(&self) -> FundBooks {
        FundBooks {
            deposits: self.deposits.clone(),
            payouts: self
                .closes
                .iter()
                .filter_map(|c| c.payout_txid.clone())
                .collect(),
        }
    }

    /// A ledger written before the books whose last close priced the units on the wallet.
    pub fn needs_reprice(&self) -> bool {
        self.books_since.is_none() && !self.closes.is_empty()
    }

    /// Moves a ledger written before the books onto them: the open period's price becomes the
    /// books' assets at the last close (`assets_zat`) over that close's units. Past closes stay
    /// as they were recorded (`books: false`); their roots are unchanged.
    pub fn reprice(&mut self, assets_zat: u64) {
        if self.books_since.is_some() {
            return;
        }
        if let Some(last) = self.closes.last() {
            self.nav = if last.total_units == 0 || assets_zat == 0 {
                Nav::PAR
            } else {
                Nav {
                    assets_zat,
                    units: last.total_units,
                }
            };
        }
        self.books_since = Some(self.period);
    }

    /// The close of the open period, valued at `assets_zat` (the books), with `cash_zat` of the
    /// books' cash and `wallet_zat` in the whole wallet. Payouts stay within the books' cash and
    /// within what the wallet can pay besides the reserve.
    pub fn plan(&self, assets_zat: u64, cash_zat: u64, wallet_zat: u64) -> Plan {
        let total = self.total_units();
        let nav = if total == 0 {
            self.nav
        } else {
            Nav {
                assets_zat,
                units: total,
            }
        };
        let held = total > 0 && assets_zat < total;
        let mut payouts: Vec<Payout> = if held {
            vec![]
        } else {
            self.queue
                .iter()
                .map(|r| Payout {
                    leaf: r.leaf.clone(),
                    units: r.units,
                    amount_zat: nav.value_of(r.units),
                    address: r.address.clone(),
                })
                .collect()
        };
        let want: u64 = payouts.iter().map(|p| p.amount_zat).sum();
        let budget = cash_zat.min(wallet_zat.saturating_sub(RESERVE_ZAT));
        let short = want > budget;
        if short {
            for p in &mut payouts {
                p.units = (p.units as u128 * budget as u128 / want as u128) as u64;
                p.amount_zat = nav.value_of(p.units);
            }
        }
        payouts.retain(|p| p.amount_zat > 0 && p.units > 0);
        Plan {
            period: self.period,
            nav,
            cash_zat,
            wallet_zat,
            payouts,
            held,
            short,
            ledger: self.digest(),
            portfolio: None,
        }
    }

    /// Applies a paid plan: burns the paid units, gives each partly paid leaf a new token (the old
    /// one was opened), keeps unpaid units queued, opens the next period at the plan's NAV.
    pub fn apply(
        &mut self,
        plan: &Plan,
        mut new_token: impl FnMut() -> [u8; 32],
    ) -> Result<Vec<Paid>, String> {
        if plan.ledger != self.digest() {
            return Err("the fund changed since this plan: make the plan again".into());
        }
        // on a copy, so a failure leaves the ledger as it was
        let mut l = self.clone();
        let paid = l.apply_to(plan, &mut new_token)?;
        *self = l;
        Ok(paid)
    }

    fn apply_to(
        &mut self,
        plan: &Plan,
        new_token: &mut impl FnMut() -> [u8; 32],
    ) -> Result<Vec<Paid>, String> {
        let mut paid = vec![];
        for p in &plan.payouts {
            let i = self
                .leaves
                .iter()
                .position(|l| l.id == p.leaf)
                .ok_or("a planned leaf is gone")?;
            let leaf = self.leaves.remove(i);
            let left = leaf.units - p.units;
            let next = match left {
                0 => None,
                _ => {
                    let t = new_token();
                    if self.leaves.iter().any(|x| x.id == hex(&units::leaf_id(&t))) {
                        return Err("a new withdraw token repeats an old one".into());
                    }
                    let l = Leaf {
                        id: hex(&units::leaf_id(&t)),
                        units: left,
                        mailbox_pk: leaf.mailbox_pk.clone(),
                    };
                    self.leaves.push(l.clone());
                    Some((t, l))
                }
            };
            // what the request asked beyond this payment stays queued, under the new leaf
            if let Some(r) = self.queue.iter_mut().find(|r| r.leaf == p.leaf) {
                r.units -= p.units.min(r.units);
                match &next {
                    Some((_, l)) if r.units > 0 => r.leaf = l.id.clone(),
                    _ => r.units = 0,
                }
            }
            paid.push(Paid {
                payout: p.clone(),
                mailbox_pk: leaf.mailbox_pk,
                next,
            });
        }
        self.queue.retain(|r| r.units > 0);
        self.nav = plan.nav;
        self.period += 1;
        Ok(paid)
    }
}

/// The fund's assets as members value them (`jitsuin fund`): cash, open receivables, overdue
/// receivables after the haircut. Give it the books' view (`Books::view`), not the wallet's.
pub fn assets(view: &FundView) -> u64 {
    let sum = |s: ReceivableStatus| -> u64 {
        view.receivables
            .iter()
            .filter(|r| r.status == s)
            .map(|r| r.outstanding_zat())
            .sum()
    };
    view.cash_zat
        + sum(ReceivableStatus::Open)
        + sum(ReceivableStatus::Overdue) * (100 - OVERDUE_HAIRCUT_PCT) / 100
}

/// Zatoshi the wallet received in `txid` (not change), once it is mined.
pub fn received(txs: &[jitsuin_wallet::WalletTx], txid: &str) -> Option<u64> {
    let tx = txs.iter().find(|t| t.txid == txid)?;
    tx.mined_height?;
    Some(
        tx.outputs
            .iter()
            .filter(|o| o.received && !o.is_change)
            .map(|o| o.value_zat)
            .sum(),
    )
}

/// A message from the fund, signed with the manager key.
pub fn message(
    kind: &str,
    key: &SigningKey,
    my_mailbox_pk: &[u8; 32],
    to: &[u8; 32],
    body: Value,
    now: u64,
) -> Result<Vec<u8>, String> {
    let mut h = message::draft(kind, my_mailbox_pk, to, None, body, &[], now);
    h["from"]["role"] = "fund".into();
    message::sign(&mut h, key);
    message::encode(&h, &[])
}

/// The wallet's transactions up to the close's root post (all of them when that post is not
/// mined or not known): the books as they stood at that close.
pub fn upto_close(
    txs: &[jitsuin_wallet::WalletTx],
    close: &Close,
) -> Vec<jitsuin_wallet::WalletTx> {
    let at = txs
        .iter()
        .find(|t| t.txid == close.root_txid)
        .and_then(|t| t.mined_height);
    txs.iter()
        .filter(|t| at.is_none_or(|h| t.mined_height.is_some_and(|m| m <= h)))
        .cloned()
        .collect()
}

/// The `fund.merkle_path` body for one leaf after a close, with the fund's books (txids only:
/// the member reads their values from the chain with the viewing key, `jitsuin fund --path`).
pub fn path_body(
    tree: &UnitTree,
    leaf: &Leaf,
    period: u32,
    portfolio: Option<&Portfolio>,
    books: &FundBooks,
) -> Option<Value> {
    let id = unhex::<32>(&leaf.id).ok()?;
    let (root, total) = tree.root();
    let mut b = json!({
        "period": period,
        "leaf_id": leaf.id,
        "units": leaf.units,
        "root": hex(&root),
        "total": total,
        "path": hex(&units::path_to_bytes(&tree.path(&id)?)),
        "books": { "deposits": books.deposits, "payouts": books.payouts },
    });
    if let Some(p) = portfolio {
        b["portfolio"] = serde_json::to_value(p).ok()?;
    }
    Some(b)
}

/// A member's mailbox key, from 64 hex characters or their contact card.
pub fn member_mailbox(s: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    let s = s.trim();
    if let Ok(pk) = unhex::<32>(&s.to_ascii_lowercase()) {
        return Some(pk);
    }
    let body = s.strip_prefix("jitsuin-contact-v1:")?;
    let card: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .ok()?,
    )
    .ok()?;
    unhex::<32>(card["mailbox_pk"].as_str()?).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdraw {
    pub token: [u8; 32],
    /// None: everything the token holds.
    pub units: Option<u64>,
    pub address: String,
}

/// A received `fund.withdraw`.
pub fn read_withdraw(h: &Value) -> Result<Withdraw, String> {
    if h["type"] != "fund.withdraw" {
        return Err("not a withdrawal request".into());
    }
    let b = &h["body"];
    let token = b["withdraw_token"]
        .as_str()
        .and_then(|t| unhex::<32>(t).ok())
        .ok_or("the request has no withdraw token")?;
    let units = match &b["units"] {
        Value::String(s) if s == "all" => None,
        v => Some(v.as_u64().ok_or("the request names no units")?),
    };
    let address = b["address"]
        .as_str()
        .ok_or("the request has no payout address")?
        .to_string();
    Ok(Withdraw {
        token,
        units,
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fund(deposits: &[u64]) -> (Ledger, Vec<[u8; 32]>) {
        let mut l = Ledger::default();
        let tokens: Vec<[u8; 32]> = (0..deposits.len() as u8).map(|i| [i + 1; 32]).collect();
        for (i, d) in deposits.iter().enumerate() {
            l.deposit(&[9; 32], *d, &format!("tx{i}"), &tokens[i])
                .unwrap();
        }
        (l, tokens)
    }

    const ADDR: &str = "utest1payoutaddressxx";

    #[test]
    fn units_start_at_par_and_later_deposits_pay_the_nav() {
        let (mut l, _) = fund(&[1_000_000, 3_000_000]);
        assert_eq!(l.total_units(), 4_000_000);
        // the fund earned 25 %: a close with nothing queued moves the price
        let plan = l.plan(5_000_000, 5_000_000, 5_000_000);
        assert!(!plan.held && plan.payouts.is_empty());
        let mut t = 50u8;
        l.apply(&plan, || {
            t += 1;
            [t; 32]
        })
        .unwrap();
        assert_eq!(l.period, 2);
        assert_eq!(
            l.deposit(&[9; 32], 1_250_000, "tx9", &[77; 32]),
            Ok(1_000_000)
        );
        assert!(l.deposit(&[9; 32], 1, "tx9", &[78; 32]).is_err());
    }

    #[test]
    fn a_withdrawal_is_paid_at_the_nav_and_the_rest_gets_a_new_token() {
        let (mut l, tok) = fund(&[1_000_000, 1_000_000]);
        assert!(l.withdraw(&[99; 32], None, ADDR, "r", 1).is_err());
        assert!(l.withdraw(&tok[0], Some(2_000_000), ADDR, "r", 1).is_err());
        l.withdraw(&tok[0], Some(400_000), ADDR, "r", 1).unwrap();
        let plan = l.plan(2_200_000, 2_200_000, 2_200_000);
        assert_eq!(plan.payouts.len(), 1);
        assert_eq!(plan.payouts[0].amount_zat, 440_000);
        let paid = l.apply(&plan, || [42; 32]).unwrap();
        let (t, leaf) = paid[0].next.clone().unwrap();
        assert_eq!(leaf.units, 600_000);
        assert!(l.queue.is_empty());
        // the opened token is spent; the new one holds what is left
        assert!(l.withdraw(&tok[0], None, ADDR, "r", 2).is_err());
        assert_eq!(l.withdraw(&t, None, ADDR, "r", 2), Ok(600_000));
        assert_eq!(l.total_units(), 1_600_000);
    }

    #[test]
    fn short_cash_pays_everyone_the_same_share_and_below_par_holds() {
        let (mut l, tok) = fund(&[1_000_000, 1_000_000]);
        l.withdraw(&tok[0], None, ADDR, "a", 1).unwrap();
        l.withdraw(&tok[1], None, ADDR, "b", 1).unwrap();
        // 2.0 M of assets, but only 1.1 M in cash (the rest is lent out)
        let plan = l.plan(2_000_000, 1_000_000 + RESERVE_ZAT, 1_000_000 + RESERVE_ZAT);
        assert!(plan.short);
        assert_eq!(plan.payouts[0].units, 500_000);
        assert_eq!(plan.payouts[1].units, 500_000);
        assert!(plan.paid_zat() <= 1_000_000);
        // one token for both new leaves would give two equal leaf ids: refused, ledger untouched
        let before = l.clone();
        l.apply(&plan, || [7; 32]).unwrap_err();
        assert_eq!(l, before);
        let mut n = 0u8;
        let paid = l
            .apply(&plan, || {
                n += 1;
                [100 + n; 32]
            })
            .unwrap();
        assert_eq!(paid.len(), 2);
        // the unpaid half stays queued under the new leaves
        assert_eq!(l.queue.len(), 2);
        assert!(l.queue.iter().all(|r| r.units == 500_000));

        let below = l.plan(900_000, 900_000, 900_000);
        assert!(below.held && below.payouts.is_empty());
    }

    #[test]
    fn a_plan_does_not_apply_to_a_changed_ledger() {
        let (mut l, tok) = fund(&[1_000_000]);
        l.withdraw(&tok[0], None, ADDR, "a", 1).unwrap();
        let plan = l.plan(1_000_000, 2_000_000, 2_000_000);
        l.deposit(&[9; 32], 5, "late", &[60; 32]).unwrap();
        assert!(l.apply(&plan, || [61; 32]).is_err());
        let mut changed = plan.clone();
        changed.payouts[0].address = "utest1someoneelsexx".into();
        assert_ne!(changed.hash(), plan.hash());
    }

    #[test]
    fn every_member_path_checks_against_the_root() {
        let (l, _) = fund(&[1, 20, 300, 4_000, 50_000]);
        let t = l.tree();
        let (root, total) = t.root();
        for leaf in &l.leaves {
            let b = path_body(&t, leaf, 1, None, &l.books()).unwrap();
            let path = units::path_from_bytes(
                &(0..b["path"].as_str().unwrap().len() / 2)
                    .map(|i| {
                        u8::from_str_radix(&b["path"].as_str().unwrap()[2 * i..2 * i + 2], 16)
                            .unwrap()
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            assert!(units::verify(
                &unhex::<32>(&leaf.id).unwrap(),
                leaf.units,
                &path,
                &root,
                total
            ));
        }
    }

    fn wallet_tx(txid: &str, height: u32, value: u64) -> jitsuin_wallet::WalletTx {
        jitsuin_wallet::WalletTx {
            txid: txid.into(),
            mined_height: Some(height),
            fee_zat: Some(10_000),
            outputs: vec![jitsuin_wallet::TxOutput {
                index: 0,
                pool: "Ironwood".into(),
                value_zat: value,
                is_change: false,
                received: true,
                memo: jitsuin_wallet::Memo::Empty,
            }],
        }
    }

    #[test]
    fn the_unit_price_comes_from_the_deposits_not_the_whole_wallet() {
        // E2E 2026-10-25: two member deposits next to 3 ZEC of the financier's own money
        let mut l = Ledger::default();
        l.deposit(&[9; 32], 30_000, "d1", &[1; 32]).unwrap();
        l.deposit(&[9; 32], 20_000, "d2", &[2; 32]).unwrap();
        let txs = vec![
            wallet_tx("own", 5, 299_860_000),
            wallet_tx("d1", 10, 30_000),
            wallet_tx("d2", 11, 20_000),
        ];
        let wallet = 299_910_000;
        let view = jitsuin_flow::fund::fund_view(&txs, wallet, &[3; 32], 100, 7);
        let books = jitsuin_flow::fund::fund_books(&view, &txs, &l.books());
        assert_eq!(books.view.cash_zat, 50_000);
        let plan = l.plan(assets(&books.view), books.view.cash_zat, wallet);
        assert_eq!(
            plan.nav,
            Nav {
                assets_zat: 50_000,
                units: 50_000
            }
        );
        // the wallet-wide price the production close showed (5998.2 zat per unit) is gone
        assert_ne!(l.plan(assets(&view), view.cash_zat, wallet).nav, plan.nav);
        l.apply(&plan, || [7; 32]).unwrap();
        assert_eq!(l.deposit(&[9; 32], 10_000, "d3", &[3; 32]), Ok(10_000));
    }

    #[test]
    fn withdrawals_are_paid_from_the_books_cash_only() {
        let (mut l, tok) = fund(&[1_000_000, 1_000_000]);
        l.withdraw(&tok[0], None, ADDR, "a", 1).unwrap();
        // the books hold 2.0 M, half of it lent out; the wallet holds 50 ZEC of other money
        let plan = l.plan(2_000_000, 600_000, 5_000_000_000);
        assert!(plan.short);
        assert!(plan.paid_zat() <= 600_000);
        assert_eq!(plan.wallet_zat, 5_000_000_000);
        // and never more than the wallet can pay besides the reserve
        let tight = l.plan(2_000_000, 2_000_000, 500_000 + RESERVE_ZAT);
        assert!(tight.short && tight.paid_zat() <= 500_000);
    }

    #[test]
    fn a_ledger_closed_on_the_wallet_is_repriced_from_the_books() {
        // the production ledger after period 1, written before the books
        let old = json!({
            "period": 2,
            "nav": { "assets_zat": 299_910_000u64, "units": 50_000 },
            "leaves": [],
            "deposits": ["d1", "d2"],
            "queue": [],
            "closes": [{
                "period": 1, "root": "2ec4", "total_units": 50_000,
                "nav": { "assets_zat": 299_910_000u64, "units": 50_000 },
                "paid_zat": 0, "payout_txid": null, "root_txid": "r1", "held": false
            }],
        });
        let mut l: Ledger = serde_json::from_value(old).unwrap();
        assert!(l.needs_reprice());
        assert!(!l.closes[0].books);
        // the books at that close: the two deposits, nothing the fund lent out
        let txs = vec![
            wallet_tx("own", 5, 299_860_000),
            wallet_tx("d1", 10, 30_000),
            wallet_tx("d2", 11, 20_000),
            wallet_tx("r1", 20, 10_000),
            wallet_tx("later", 30, 70_000),
        ];
        let at = upto_close(&txs, &l.closes[0]);
        assert_eq!(at.len(), 4);
        let view = jitsuin_flow::fund::fund_view(&at, 0, &[3; 32], 100, 7);
        let books = jitsuin_flow::fund::fund_books(&view, &at, &l.books());
        l.reprice(assets(&books.view));
        assert_eq!(
            l.nav,
            Nav {
                assets_zat: 50_000,
                units: 50_000
            }
        );
        assert_eq!(l.books_since, Some(2));
        assert!(!l.needs_reprice());
        // the closed period's record and root stay as they were
        assert_eq!(l.closes[0].root, "2ec4");
        l.reprice(1);
        assert_eq!(l.nav.assets_zat, 50_000);
        // a new ledger is on the books from the start
        assert!(!Ledger::default().needs_reprice());
    }

    #[test]
    fn a_member_path_carries_the_books() {
        let (mut l, _) = fund(&[1_000]);
        l.closes.push(Close {
            period: 1,
            root: String::new(),
            total_units: 1_000,
            nav: Nav::PAR,
            paid_zat: 5,
            payout_txid: Some("p1".into()),
            root_txid: String::new(),
            held: false,
            books: true,
        });
        let b = path_body(&l.tree(), &l.leaves[0], 1, None, &l.books()).unwrap();
        assert_eq!(
            b["books"],
            json!({ "deposits": ["tx0"], "payouts": ["p1"] })
        );
    }

    #[test]
    fn the_portfolio_counts_receivables_without_naming_them() {
        use jitsuin_flow::fund::Receivable;
        let r = |due: u32, face: u64, repaid: u64, status| Receivable {
            nullifier: [1; 32],
            face_zat: face,
            due_date: due,
            advance_zat: 1,
            advance_txid: "t".into(),
            repaid_zat: repaid,
            status,
        };
        let view = FundView {
            cash_zat: 500,
            receivables: vec![
                r(110, 1_000, 0, ReceivableStatus::Open),
                r(150, 2_000, 500, ReceivableStatus::Open),
                r(400, 3_000, 0, ReceivableStatus::Open),
                r(50, 4_000, 0, ReceivableStatus::Overdue),
                r(60, 5_000, 5_000, ReceivableStatus::Repaid),
            ],
            root: None,
            ignored_roots: 0,
        };
        let p = portfolio(&view, 100);
        assert_eq!(
            (p.open, p.open_zat, p.overdue, p.overdue_zat, p.repaid),
            (3, 5_500, 1, 4_000, 1)
        );
        assert_eq!(p.due_within, [1, 1, 1]);
        assert!(!serde_json::to_string(&p).unwrap().contains("0101"));
    }

    #[test]
    fn a_member_is_named_by_key_or_card() {
        let card = crate::relay::contact_card(&[4; 32], &[1; 32]);
        assert_eq!(member_mailbox(&card), Some([4; 32]));
        assert_eq!(member_mailbox(&hex(&[4; 32])), Some([4; 32]));
        assert_eq!(member_mailbox("nope"), None);
    }

    #[test]
    fn a_withdraw_message_reads_back() {
        let me = [3u8; 32];
        let h = json!({
            "type": "fund.withdraw",
            "from": { "role": "member", "mailbox_pk": hex(&me) },
            "body": { "withdraw_token": hex(&[5; 32]), "units": "all", "address": ADDR, "period": 1 },
        });
        assert_eq!(
            read_withdraw(&h),
            Ok(Withdraw {
                token: [5; 32],
                units: None,
                address: ADDR.into()
            })
        );
        let mut some = h.clone();
        some["body"]["units"] = 7.into();
        assert_eq!(read_withdraw(&some).unwrap().units, Some(7));
    }
}
