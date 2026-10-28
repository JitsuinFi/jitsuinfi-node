//! The node's wallet for its own console (`/node/console/wallet`): the balance, what a send can
//! use now, the fund's share of it, a top-up address and the latest transactions, so the
//! financier never needs a terminal or a faucet page to see or fill the wallet that pays board
//! entries, advances, `settled` entries and fund payouts.
//!
//! The whole wallet is not the fund (see `fund.rs`): `fund_cash_zat` is the books' cash, the
//! members' money; `own_zat` is the rest, the financier's own.
//!
//! The pay preflight (`short`) refuses an advance the wallet cannot cover with the network fee
//! before the operator is asked for a passkey, and again before the node pays.

use std::collections::HashMap;
use std::path::Path;

use jitsuin_core::{MemoItem, ReceiptKind};
use jitsuin_wallet::{Memo, WalletTx};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The network fee the node assumes per send (ZIP-317 for the node's two-action sends, as the
/// board entry, the advance and the `settled` entry pay today).
pub const FEE_ZAT: u64 = 10_000;
/// The top-up address, made once and kept in the node's volume.
pub const TOPUP_FILE: &str = "wallet-topup.json";
/// Transactions listed in the console.
pub const MAX_TXS: usize = 30;

/// What the wallet holds after a sync.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub txs: Vec<WalletTx>,
    /// Whole wallet, every pool, spendable or pending (`Devtool::balance_zat`).
    pub balance_zat: u64,
    pub spendable_zat: u64,
    pub pending_zat: u64,
    /// The wallet's net change per txid (`deltas`).
    pub deltas: HashMap<String, i64>,
    /// Unix seconds of the sync.
    pub synced_at: u64,
}

/// Spendable and pending value in `zcash-devtool wallet balance` output (the same Debug dump that
/// `jitsuin_wallet::parse_balance` reads): `spendable_value` sums into spendable,
/// `change_pending_confirmation` and `value_pending_spendability` into pending. `None` when the
/// output carries no balance.
pub fn parse_split(out: &str) -> Option<(u64, u64)> {
    let compact: String = out.chars().filter(|c| !c.is_whitespace()).collect();
    if !compact.contains("account_balances") {
        return None;
    }
    let sum = |field: &str| -> Option<u64> {
        let mut total: u64 = 0;
        for (i, _) in compact.match_indices(field) {
            let digits: String = compact[i + field.len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            total = total.checked_add(digits.parse().ok()?)?;
        }
        Some(total)
    };
    let spendable = sum("spendable_value:Zatoshis(")?;
    let pending = sum("change_pending_confirmation:Zatoshis(")?
        .checked_add(sum("value_pending_spendability:Zatoshis(")?)?;
    Some((spendable, pending))
}

/// The output of one `zcash-devtool wallet` command (`balance`, `list-tx`), run directly: the
/// wallet crate gives only the balance's total and drops `list-tx`'s per-transaction amount.
pub fn devtool_output(devtool: &Path, wallet_dir: &Path, command: &str) -> Result<String, String> {
    let out = std::process::Command::new(devtool)
        .arg("wallet")
        .arg("-w")
        .arg(wallet_dir)
        .arg(command)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("cannot run zcash-devtool: {e}"))?;
    if !out.status.success() {
        return Err(format!("zcash-devtool could not run {command}"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A devtool amount (`  1.23450000 TAZ`, `-2.00000000 TAZ`) in zatoshi with its sign as printed.
fn zat_amount(s: &str) -> Option<i64> {
    let s = s.trim();
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r.trim_start()),
        None => (false, s),
    };
    let num = s.split_whitespace().next()?;
    let (whole, frac) = num.split_once('.').unwrap_or((num, "0"));
    let frac = format!("{frac:0<8}");
    if frac.len() != 8 {
        return None;
    }
    let v = whole.parse::<i64>().ok()?.checked_mul(100_000_000)? + frac.parse::<i64>().ok()?;
    Some(if neg { -v } else { v })
}

#[derive(Default)]
struct TxLines {
    amount: Option<i64>,
    fee: i64,
    sent_notes: u32,
    /// Outputs: value, received from outside ("Received by account"), sent out ("Sent from
    /// account"). Change and transfers inside the wallet carry neither line.
    outputs: Vec<(i64, bool, bool)>,
}

impl TxLines {
    /// The node spent notes in this transaction.
    fn ours(&self) -> bool {
        self.sent_notes > 0 || self.outputs.iter().any(|o| !o.1)
    }

    fn delta(&self) -> i64 {
        let ours = self.ours();
        match self.amount {
            // devtool prints the wallet's `account_balance_delta`, but loses the minus sign below
            // 1 ZEC (`format_zec` signs the whole part, which is 0): a transaction the wallet
            // paid for is a decrease
            Some(a) if ours => -a.abs(),
            Some(a) => a,
            None if ours => {
                -(self
                    .outputs
                    .iter()
                    .filter(|o| o.2)
                    .map(|o| o.0)
                    .sum::<i64>()
                    + self.fee)
            }
            None => self.outputs.iter().filter(|o| o.1).map(|o| o.0).sum(),
        }
    }
}

/// The wallet's net change per transaction from `zcash-devtool wallet list-tx`: the wallet's own
/// `Amount` (`account_balance_delta`: received notes, change included, minus spent notes), signed
/// by whether the wallet spent notes in it. Without an `Amount`: what left the wallet plus the
/// fee for a transaction it paid, what arrived for one it did not.
pub fn deltas(list_tx: &str) -> HashMap<String, i64> {
    let mut txs: Vec<(String, TxLines)> = Vec::new();
    for raw in list_tx.lines() {
        let line = raw.trim();
        if line.len() == 64 && line.bytes().all(|b| b.is_ascii_hexdigit()) {
            txs.push((line.to_string(), TxLines::default()));
            continue;
        }
        let Some((_, t)) = txs.last_mut() else {
            continue;
        };
        if let Some(r) = line.strip_prefix("Amount:") {
            t.amount = zat_amount(r);
        } else if let Some(r) = line.strip_prefix("Fee paid:") {
            t.fee = zat_amount(r).unwrap_or(0);
        } else if line.starts_with("Sent from account:") {
            if let Some(o) = t.outputs.last_mut() {
                o.2 = true;
            }
        } else if let Some(r) = line.strip_prefix("Sent ") {
            t.sent_notes = r
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
        } else if let Some(r) = line.strip_prefix("Value:") {
            t.outputs.push((zat_amount(r).unwrap_or(0), false, false));
        } else if line.starts_with("Received by account:") {
            if let Some(o) = t.outputs.last_mut() {
                o.1 = true;
            }
        }
    }
    txs.into_iter().map(|(id, t)| (id, t.delta())).collect()
}

#[derive(Serialize, Deserialize)]
struct Topup {
    address: String,
    created_at: u64,
}

/// The top-up address saved in `dir`, if any.
pub fn saved_topup(dir: &Path) -> Option<String> {
    std::fs::read(dir.join(TOPUP_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice::<Topup>(&b).ok())
        .map(|t| t.address)
        .filter(|a| (10..=512).contains(&a.len()) && a.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// The node's top-up address: the one saved in `dir`, else a new one from `make`, saved before
/// it is shown, so every later call gets the same address.
pub fn topup_address(
    dir: &Path,
    now: u64,
    make: impl FnOnce() -> Result<String, String>,
) -> Result<String, String> {
    if let Some(a) = saved_topup(dir) {
        return Ok(a);
    }
    let address = make()?;
    let tmp = dir.join(format!("{TOPUP_FILE}.tmp"));
    let body = serde_json::to_vec(&Topup {
        address: address.clone(),
        created_at: now,
    })
    .expect("json");
    std::fs::write(&tmp, body)
        .and_then(|_| std::fs::rename(&tmp, dir.join(TOPUP_FILE)))
        .map_err(|e| format!("the node could not save its top-up address: {e}"))?;
    Ok(address)
}

/// What the node knows of its own transactions, by txid.
#[derive(Debug, Default)]
pub struct Known(pub HashMap<String, &'static str>);

impl Known {
    pub fn add(&mut self, txid: Option<&str>, kind: &'static str) {
        if let Some(t) = txid.filter(|t| !t.is_empty()) {
            self.0.entry(t.to_string()).or_insert(kind);
        }
    }
}

fn repayment(tx: &WalletTx) -> bool {
    tx.outputs.iter().any(|o| {
        o.received
            && match &o.memo {
                Memo::Arbitrary(b) => jitsuin_core::memo::decode(b)
                    .unwrap_or_default()
                    .iter()
                    .any(|i| matches!(i, MemoItem::Receipt(r) if r.kind == ReceiptKind::Repayment)),
                _ => false,
            }
    })
}

/// The kind the console shows: from the deals and the fund ledger first; else a repayment by its
/// receipt memo; else money that came in from outside is a top-up; else "other".
pub fn kind(tx: &WalletTx, delta: i64, known: &Known) -> &'static str {
    if let Some(k) = known.0.get(&tx.txid) {
        return k;
    }
    if repayment(tx) {
        "repayment"
    } else if delta > 0 {
        "topup"
    } else {
        "other"
    }
}

/// The latest `MAX_TXS` transactions, newest first: not yet mined, then by height.
pub fn txs(all: &[WalletTx], deltas: &HashMap<String, i64>, known: &Known) -> Vec<Value> {
    let mut v: Vec<&WalletTx> = all.iter().rev().collect();
    v.sort_by_key(|t| std::cmp::Reverse(t.mined_height.unwrap_or(u32::MAX)));
    v.into_iter()
        .take(MAX_TXS)
        .map(|t| {
            let delta = deltas.get(&t.txid).copied().unwrap_or(0);
            json!({
                "txid": t.txid,
                "height": t.mined_height,
                "delta_zat": delta,
                "kind": kind(t, delta, known),
            })
        })
        .collect()
}

/// The `/node/console/wallet` answer.
pub fn view(s: &Snapshot, fund_cash: Option<u64>, topup: &str, known: &Known) -> Value {
    json!({
        "balance_zat": s.balance_zat,
        "spendable_zat": s.spendable_zat,
        "pending_zat": s.pending_zat,
        "fund_cash_zat": fund_cash,
        "own_zat": fund_cash.map(|c| s.balance_zat.saturating_sub(c)),
        "fee_zat": FEE_ZAT,
        "topup_address": topup,
        "topup_uri": format!("zcash:{topup}"),
        "txs": txs(&s.txs, &s.deltas, known),
        "synced_at": s.synced_at,
    })
}

/// Zatoshi shown as ZEC with up to 8 decimals, trailing zeros dropped.
pub fn zec(zat: u64) -> String {
    let s = format!("{}.{:08}", zat / 100_000_000, zat % 100_000_000);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// The pay preflight: `Some(error body)` when `spendable` cannot pay `advance` plus the fee.
pub fn short(spendable: u64, advance: u64) -> Option<Value> {
    let need = advance.saturating_add(FEE_ZAT);
    (spendable < need).then(|| {
        json!({
            "error": format!(
                "The node's wallet holds {} ZEC; this advance needs {} ZEC plus a {} ZEC network fee. Top up the node first.",
                zec(spendable),
                zec(advance),
                zec(FEE_ZAT)
            ),
            "need_zat": need,
            "spendable_zat": spendable,
            "advance_zat": advance,
            "fee_zat": FEE_ZAT,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitsuin_wallet::TxOutput;

    fn out(value: u64, received: bool, change: bool) -> TxOutput {
        TxOutput {
            index: 0,
            pool: "Orchard".into(),
            value_zat: value,
            is_change: change,
            received,
            memo: Memo::Empty,
        }
    }

    fn tx(id: &str, h: Option<u32>, fee: Option<u64>, outputs: Vec<TxOutput>) -> WalletTx {
        WalletTx {
            txid: id.into(),
            mined_height: h,
            fee_zat: fee,
            outputs,
        }
    }

    const BALANCE: &str = "WalletSummary { account_balances: {AccountUuid(1): AccountBalance {
        sapling_balance: Balance { spendable_value: Zatoshis(0), change_pending_confirmation: Zatoshis(0), value_pending_spendability: Zatoshis(0), uneconomic_value: Zatoshis(0) },
        orchard_balance: Balance { spendable_value: Zatoshis(250000000), change_pending_confirmation: Zatoshis(40000), value_pending_spendability: Zatoshis(1000000), uneconomic_value: Zatoshis(0) },
        unshielded_balance: Balance { spendable_value: Zatoshis(5), change_pending_confirmation: Zatoshis(0), value_pending_spendability: Zatoshis(0), uneconomic_value: Zatoshis(0) } }} }";

    #[test]
    fn the_balance_splits_into_spendable_and_pending() {
        assert_eq!(parse_split(BALANCE), Some((250_000_005, 1_040_000)));
        assert_eq!(
            jitsuin_wallet::parse_balance(BALANCE).unwrap(),
            251_040_005,
            "balance_zat is the whole wallet"
        );
        // the devtool sample of jitsuin-wallet's own test (`parses_balance_of_every_pool`)
        let real = "WalletSummary { account_balances: { AccountUuid(x): AccountBalance {
            sapling_balance: Balance { spendable_value: Zatoshis(\n 5,\n), locked_value: Zatoshis(0,),
              change_pending_confirmation: Zatoshis(0,), value_pending_spendability: Zatoshis(0,),
              uneconomic_value: Zatoshis(0,), },
            ironwood_balance: Balance { spendable_value: Zatoshis(99592000,), locked_value: Zatoshis(0,),
              change_pending_confirmation: Zatoshis(10000,), value_pending_spendability: Zatoshis(3,),
              uneconomic_value: Zatoshis(0,), }, }, }, chain_tip_height: BlockHeight(4511015,) }";
        assert_eq!(parse_split(real), Some((99_592_005, 10_003)));
        assert_eq!(jitsuin_wallet::parse_balance(real).unwrap(), 99_602_008);
        assert_eq!(parse_split("no wallet"), None);
    }

    #[test]
    fn the_answer_has_the_console_contract() {
        let s = Snapshot {
            txs: vec![
                tx("a", Some(10), None, vec![out(300_000_000, true, false)]),
                tx(
                    "b",
                    Some(12),
                    Some(10_000),
                    vec![out(50_000_000, false, false), out(1_000, true, true)],
                ),
                tx("c", None, Some(10_000), vec![out(10_000, false, false)]),
                tx("d", Some(11), None, vec![out(7, true, false)]),
            ],
            balance_zat: 250_000_000,
            spendable_zat: 249_000_000,
            pending_zat: 1_000_000,
            deltas: [
                ("a", 300_000_000),
                ("b", -50_010_000),
                ("c", -20_000),
                ("d", 7),
            ]
            .into_iter()
            .map(|(t, d)| (t.to_string(), d))
            .collect(),
            synced_at: 1_800_000_000,
        };
        let mut known = Known::default();
        known.add(Some("b"), "advance");
        known.add(Some("c"), "entry");
        known.add(Some("d"), "deposit");
        let v = view(&s, Some(100_000_000), "utest1top", &known);
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        let mut want = vec![
            "balance_zat",
            "spendable_zat",
            "pending_zat",
            "fund_cash_zat",
            "own_zat",
            "fee_zat",
            "topup_address",
            "topup_uri",
            "txs",
            "synced_at",
        ];
        want.sort();
        let mut got = keys.clone();
        got.sort();
        assert_eq!(got, want);
        assert_eq!(v["own_zat"], 150_000_000);
        assert_eq!(v["fee_zat"], 10_000);
        assert_eq!(v["topup_uri"], "zcash:utest1top");
        let t = v["txs"].as_array().unwrap();
        let ids: Vec<&str> = t.iter().map(|x| x["txid"].as_str().unwrap()).collect();
        assert_eq!(ids, ["c", "b", "d", "a"], "unmined first, then newest");
        assert_eq!(t[0]["height"], Value::Null);
        assert_eq!(t[0]["kind"], "entry");
        assert_eq!(t[1]["delta_zat"], -50_010_000);
        assert_eq!(t[1]["kind"], "advance");
        assert_eq!(t[2]["kind"], "deposit");
        assert_eq!(t[3]["kind"], "topup");
        assert_eq!(t[3]["delta_zat"], 300_000_000);
        for x in t {
            assert_eq!(x.as_object().unwrap().len(), 4);
        }
        // no fund: both null
        let v = view(&s, None, "utest1top", &known);
        assert!(v["fund_cash_zat"].is_null() && v["own_zat"].is_null());
        // a fund larger than the wallet: own is 0, not negative
        assert_eq!(view(&s, Some(300_000_000), "u", &known)["own_zat"], 0);
    }

    #[test]
    fn at_most_thirty_transactions() {
        let all: Vec<WalletTx> = (0..40)
            .map(|i| tx(&format!("t{i}"), Some(i), None, vec![out(1, true, false)]))
            .collect();
        let v = txs(&all, &HashMap::new(), &Known::default());
        assert_eq!(v.len(), MAX_TXS);
        assert_eq!(v[0]["txid"], "t39");
    }

    /// `zcash-devtool wallet list-tx` as the pinned revision prints it (`list_tx.rs`
    /// `print_text`): `Amount` is the wallet's `account_balance_delta`, printed without its minus
    /// sign below 1 ZEC; change and transfers inside the wallet carry no account line.
    const LIST_TX: &str = "Transactions:
1111111111111111111111111111111111111111111111111111111111111111
     Mined: 4600000 (2026-10-27 10:00:00.0 +00:00:00)
    Amount:   1.00000000 TAZ
  Fee paid:   0.00010000 TAZ
  Sent 0 notes, received 1 notes, 0 memos
  Output 0 (Orchard)
    Value:   1.00000000 TAZ
    Received by account: 0c6b7a52-6f0e-4f7e-9c51-2a7c1f6d5a10 (financier)
2222222222222222222222222222222222222222222222222222222222222222
     Mined: 4600100 (2026-10-27 12:00:00.0 +00:00:00)
    Amount:   0.00100000 TAZ
  Fee paid:   0.00010000 TAZ
  Sent 1 notes, received 1 notes, 1 memos
  Output 0 (Orchard)
    Value:   0.00090000 TAZ
    Sent from account: 0c6b7a52-6f0e-4f7e-9c51-2a7c1f6d5a10 (financier)
    To: utest1supplier
    Memo: Memo::Arbitrary([255, 74, 84])
  Output 1 (Orchard)
    Value:   0.99740000 TAZ (Change)
3333333333333333333333333333333333333333333333333333333333333333
     Mined: 4600200 (2026-10-27 14:00:00.0 +00:00:00)
    Amount:   0.00100000 TAZ
  Fee paid:   0.00010000 TAZ
  Sent 0 notes, received 1 notes, 1 memos
  Output 0 (Orchard)
    Value:   0.00100000 TAZ
    Received by account: 0c6b7a52-6f0e-4f7e-9c51-2a7c1f6d5a10 (financier)
    Memo: Memo::Arbitrary([255, 74, 84])
4444444444444444444444444444444444444444444444444444444444444444
     Mined: 4600300 (2026-10-27 16:00:00.0 +00:00:00)
    Amount:   0.00010000 TAZ
  Fee paid:   0.00010000 TAZ
  Sent 1 notes, received 2 notes, 1 memos
  Output 0 (Orchard)
    Value:   0.00010000 TAZ (Wallet Internal Transfer)
    To: utest1financier
    Memo: Memo::Arbitrary([255, 74, 84])
  Output 1 (Orchard)
    Value:   0.99620000 TAZ (Change)
5555555555555555555555555555555555555555555555555555555555555555
     Mined: 4600400 (2026-10-27 18:00:00.0 +00:00:00)
    Amount:   0.00020000 TAZ
  Fee paid:   0.00010000 TAZ
  Sent 1 notes, received 1 notes, 1 memos
  Output 0 (Orchard)
    Value:   0.00010000 TAZ
    Sent from account: 0c6b7a52-6f0e-4f7e-9c51-2a7c1f6d5a10 (financier)
    To: utest1board
    Memo: Memo::Arbitrary([255, 74, 84])
  Output 1 (Orchard)
    Value:   0.99600000 TAZ (Change)
6666666666666666666666666666666666666666666666666666666666666666
     Mined: 4600500 (2026-10-27 20:00:00.0 +00:00:00)
    Amount:  -1.50010000 TAZ
  Fee paid:   0.00010000 TAZ
  Sent 2 notes, received 1 notes, 0 memos
  Output 0 (Orchard)
    Value:   1.50000000 TAZ
    Sent from account: 0c6b7a52-6f0e-4f7e-9c51-2a7c1f6d5a10 (financier)
    To: utest1member
  Output 1 (Orchard)
    Value:   0.49590000 TAZ (Change)
7777777777777777777777777777777777777777777777777777777777777777
     Unmined (expiry height: 4600640)
  Fee paid:   0.00010000 TAZ
  Sent 1 notes, received 1 notes, 0 memos
  Output 0 (Orchard)
    Value:   0.00090000 TAZ
    Sent from account: 0c6b7a52-6f0e-4f7e-9c51-2a7c1f6d5a10 (financier)
  Output 1 (Orchard)
    Value:   0.49490000 TAZ (Change)
";

    #[test]
    fn deltas_are_the_wallets_own_amounts() {
        let d = deltas(LIST_TX);
        let at = |c: char| d[&c.to_string().repeat(64)];
        assert_eq!(at('1'), 100_000_000, "top-up: +received");
        assert_eq!(at('2'), -100_000, "advance with change: -(0.0009 + fee)");
        assert_eq!(
            at('3'),
            100_000,
            "repayment: +received, the sender's fee is not ours"
        );
        assert_eq!(at('4'), -10_000, "self-send with change (fund root): -fee");
        assert_eq!(
            at('5'),
            -20_000,
            "entry or settled to the board: -(0.0001 + fee)"
        );
        assert_eq!(
            at('6'),
            -150_010_000,
            "a payout over 1 ZEC keeps its printed sign"
        );
        assert_eq!(at('7'), -100_000, "no Amount line: what left plus the fee");
        // the kinds follow the sign
        let txs = jitsuin_wallet::parse_list_tx(LIST_TX).unwrap();
        let k = |c: char| {
            let t = txs
                .iter()
                .find(|t| t.txid == c.to_string().repeat(64))
                .unwrap();
            kind(t, at(c), &Known::default())
        };
        assert_eq!((k('1'), k('4'), k('5')), ("topup", "other", "other"));
    }

    #[test]
    fn amounts_parse_as_devtool_prints_them() {
        assert_eq!(zat_amount("  0.00090000 TAZ"), Some(90_000));
        assert_eq!(zat_amount(" -1.50010000 TAZ"), Some(-150_010_000));
        assert_eq!(zat_amount("  3.99000000 ZEC"), Some(399_000_000));
        assert_eq!(zat_amount("Unknown"), None);
    }

    #[test]
    fn the_topup_address_is_made_once_and_kept() {
        let dir = std::env::temp_dir().join(format!("jitsuin-topup-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = "utest1".to_string() + &"q".repeat(100);
        let mut made = 0;
        let first = topup_address(&dir, 1, || {
            made += 1;
            Ok(a.clone())
        })
        .unwrap();
        let again = topup_address(&dir, 2, || {
            made += 1;
            Ok("utest1other".repeat(10))
        })
        .unwrap();
        assert_eq!(
            (first.as_str(), again.as_str(), made),
            (a.as_str(), a.as_str(), 1)
        );
        assert!(dir.join(TOPUP_FILE).exists());
        // a failed make saves nothing
        let empty = dir.join("x");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(topup_address(&empty, 1, || Err("no".into())).is_err());
        assert!(!empty.join(TOPUP_FILE).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_preflight_refuses_an_advance_the_wallet_cannot_pay() {
        assert!(short(50_010_000, 50_000_000).is_none());
        let e = short(50_009_999, 50_000_000).unwrap();
        assert_eq!(e["need_zat"], 50_010_000);
        assert_eq!(e["spendable_zat"], 50_009_999);
        assert_eq!(
            e["error"],
            "The node's wallet holds 0.50009999 ZEC; this advance needs 0.5 ZEC plus a 0.0001 ZEC network fee. Top up the node first."
        );
        assert!(short(0, u64::MAX).is_some(), "no overflow");
        assert_eq!(zec(0), "0");
        assert_eq!(zec(123_400_000), "1.234");
    }
}
