//! Due-date reminders to the buyer (buyer-late): a financed deal that is not settled yet sends the
//! buyer's mailbox a `deal.reminder` at three milestones, seven days and one day before the due
//! date and one day after it. The buyer's mailbox is the one the supplier named in the offer
//! (`Accepted::buyer_mailbox_pk`, where the letter and the financier's seal already go); without
//! it there is no reminder. The message is signed with the financier key that signed the letter,
//! so the buyer's screen checks it against the letter it keeps: no new key, no new secret.
//!
//! Each milestone goes out once (`Meta::reminders` records it after the relay took it), and only
//! the latest one reached: a node that was down at D-7 sends D-1 or D+1, not a stale D-7 after
//! it. Nothing goes out once the repayment covers the amount (pending or settled).

use ed25519_dalek::SigningKey;
use serde_json::json;

use crate::message;

/// The milestones, in order, as days from the due date.
pub const MILESTONES: [(&str, i64); 3] = [("d-7", -7), ("d-1", -1), ("d+1", 1)];

/// What the deal holds that decides a reminder.
pub struct Due<'a> {
    /// Days since the epoch.
    pub due_date: u32,
    pub today: u32,
    /// Milestones already sent.
    pub sent: &'a [String],
    /// The repayment status as `drive` last saw it (`Status` in words), if read.
    pub repayment: Option<&'a str>,
    /// The `settled` entry is posted.
    pub settled: bool,
    /// The offer named the buyer's mailbox.
    pub buyer_known: bool,
}

/// The milestone to send now, if any.
pub fn next(d: &Due) -> Option<&'static str> {
    if d.settled || !d.buyer_known || matches!(d.repayment, Some("Settled" | "Pending")) {
        return None;
    }
    let (name, _) = MILESTONES
        .iter()
        .rev()
        .find(|(_, off)| i64::from(d.today) >= i64::from(d.due_date) + off)?;
    (!d.sent.iter().any(|s| s == name)).then_some(*name)
}

/// `deal.reminder` to the buyer for invoice `n`: the milestone, the due date and the amount, all
/// of which the buyer already holds in the invoice and the letter.
#[allow(clippy::too_many_arguments)]
pub fn reminder_message(
    key: &SigningKey,
    me: &[u8; 32],
    to: &[u8; 32],
    n: &str,
    milestone: &str,
    due_date: u32,
    amount_zat: u64,
    now: u64,
) -> Result<Vec<u8>, String> {
    let body = json!({ "milestone": milestone, "due_date": due_date, "amount_zat": amount_zat });
    let mut h = message::draft("deal.reminder", me, to, Some(n), body, &[], now);
    message::sign(&mut h, key);
    message::encode(&h, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUE: u32 = 20_754;

    fn due<'a>(today: u32, sent: &'a [String]) -> Due<'a> {
        Due {
            due_date: DUE,
            today,
            sent,
            repayment: Some("Unpaid"),
            settled: false,
            buyer_known: true,
        }
    }

    #[test]
    fn each_milestone_goes_out_on_its_day_and_once() {
        let none: Vec<String> = vec![];
        assert_eq!(next(&due(DUE - 8, &none)), None);
        assert_eq!(next(&due(DUE - 7, &none)), Some("d-7"));
        assert_eq!(next(&due(DUE - 3, &none)), Some("d-7"));
        let d7 = vec!["d-7".to_string()];
        assert_eq!(next(&due(DUE - 3, &d7)), None, "sent once");
        assert_eq!(next(&due(DUE - 1, &d7)), Some("d-1"));
        // the due date itself: still on time, nothing new
        let d1 = vec!["d-7".to_string(), "d-1".to_string()];
        assert_eq!(next(&due(DUE, &d1)), None);
        assert_eq!(next(&due(DUE + 1, &d1)), Some("d+1"));
        let all = vec!["d-7".to_string(), "d-1".to_string(), "d+1".to_string()];
        assert_eq!(next(&due(DUE + 30, &all)), None, "nothing after D+1");
    }

    #[test]
    fn a_node_that_was_down_sends_only_the_latest_milestone() {
        let none: Vec<String> = vec![];
        assert_eq!(next(&due(DUE - 1, &none)), Some("d-1"));
        assert_eq!(next(&due(DUE + 4, &none)), Some("d+1"));
        let late = vec!["d+1".to_string()];
        assert_eq!(next(&due(DUE + 5, &late)), None, "no stale D-7 after D+1");
    }

    #[test]
    fn no_reminder_once_paid_or_without_the_buyers_mailbox() {
        let none: Vec<String> = vec![];
        for r in ["Settled", "Pending"] {
            let d = Due {
                repayment: Some(r),
                ..due(DUE - 1, &none)
            };
            assert_eq!(next(&d), None, "{r}");
        }
        // a partial payment or a bare claim still gets the reminder
        for r in ["Partial", "Claimed", "Overdue"] {
            let d = Due {
                repayment: Some(r),
                ..due(DUE + 1, &none)
            };
            assert_eq!(next(&d), Some("d+1"), "{r}");
        }
        assert_eq!(
            next(&Due {
                settled: true,
                ..due(DUE - 1, &none)
            }),
            None
        );
        assert_eq!(
            next(&Due {
                buyer_known: false,
                ..due(DUE - 1, &none)
            }),
            None
        );
    }

    #[test]
    fn the_reminder_is_signed_by_the_financier_and_names_the_deal() {
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let buyer = jitsuin_core::mailbox::MailboxKeys::from_prf(&[2; 32]);
        let n = "ab".repeat(32);
        let bytes = reminder_message(
            &key,
            &[1; 32],
            &buyer.public(),
            &n,
            "d-1",
            DUE,
            60_000,
            1_792_400_000,
        )
        .unwrap();
        let m = message::decode(&bytes, &message::hex(&buyer.id())).unwrap();
        let h = &m.header;
        assert_eq!(h["type"], "deal.reminder");
        assert_eq!(h["n"], n.as_str());
        assert_eq!(
            h["body"],
            json!({ "milestone": "d-1", "due_date": DUE, "amount_zat": 60_000 })
        );
        assert!(m.attachments.is_empty());
        assert!(message::verify(
            h,
            Some(&message::hex(&key.verifying_key().to_bytes()))
        ));
    }
}
