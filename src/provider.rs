//! The node provider's side of financier applications (HNK-26.T25, D-46 B). Runs on the
//! provider's own machine, not on a node, and needs no node settings:
//!
//! - `jitsuin-node provider init`: makes the provider key (32 random bytes, mode 0600, in
//!   `$JITSUIN_PROVIDER_DIR` or `~/.jitsuin-provider`), registers its mailbox at the relay and
//!   prints the two public values the web app needs (mailbox key, signing key).
//! - `jitsuin-node provider inbox`: opens the sealed `financier.apply` messages (name, contact,
//!   note, reply mailbox) and lists them.
//! - `jitsuin-node provider invite <reply_mailbox_pk> <invite_link>`: sends the applicant a
//!   `financier.invite` signed with the provider key, sealed to its mailbox.
//! - `jitsuin-node provider remove <relay_id>`: removes a handled application at the relay.
//! - `jitsuin-node provider directory add|remove|list|publish`: the financier directory (D-47,
//!   `directory.rs`), kept next to the key and published signed with it.
//!
//! Keys from the provider key, as the node's (BLAKE2b, personalizations `JitsuinProvSig__`,
//! `JitsuinProvMbox_`). Applications travel sealed; the relay sees ciphertext only.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use blake2b_simd::Params;
use ed25519_dalek::SigningKey;
use jitsuin_core::mailbox::MailboxKeys;
use rand::RngCore;
use serde_json::{json, Map, Value};

use crate::directory;
use crate::message::{self, hex, unhex};
use crate::relay::Relay;

fn derive(master: &[u8; 32], personal: &[u8; 16], label: &[u8]) -> [u8; 32] {
    let h = Params::new()
        .hash_length(32)
        .key(master)
        .personal(personal)
        .to_state()
        .update(label)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

struct Provider {
    signer: SigningKey,
    mailbox: MailboxKeys,
}

fn dir() -> PathBuf {
    std::env::var_os("JITSUIN_PROVIDER_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".jitsuin-provider")
        })
}

fn load(create: bool) -> Result<Provider, String> {
    let path = dir().join("provider.key");
    let master: [u8; 32] = if path.exists() {
        fs::read(&path)
            .map_err(|e| e.to_string())?
            .as_slice()
            .try_into()
            .map_err(|_| "provider.key is not 32 bytes")?
    } else if create {
        fs::create_dir_all(dir()).map_err(|e| e.to_string())?;
        let mut m = [0u8; 32];
        rand::rng().fill_bytes(&mut m);
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&path)
            .and_then(|mut f| f.write_all(&m))
            .map_err(|e| e.to_string())?;
        m
    } else {
        return Err(format!(
            "no provider key at {}: run `jitsuin-node provider init`",
            path.display()
        ));
    };
    Ok(Provider {
        signer: SigningKey::from_bytes(&derive(&master, b"JitsuinProvSig__", b"signer")),
        mailbox: MailboxKeys::from_prf(&derive(&master, b"JitsuinProvMbox_", b"mailbox")),
    })
}

fn relay() -> Result<Relay, String> {
    Relay::new(
        &std::env::var("RELAY_URL")
            .unwrap_or_else(|_| "https://relay-production-27dc.up.railway.app".into()),
    )
    .map_err(|e| e.to_string())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The signed invite header (type `financier.invite`, from the provider to the applicant).
fn invite_header(p: &Provider, to: &[u8; 32], link: &str) -> Value {
    let mut m = Map::new();
    m.insert("v".into(), 1.into());
    m.insert("id".into(), message::random_id().into());
    m.insert("type".into(), "financier.invite".into());
    m.insert(
        "to".into(),
        hex(&jitsuin_core::mailbox::mailbox_id(to)).into(),
    );
    m.insert(
        "from".into(),
        json!({ "role": "provider", "mailbox_pk": hex(&p.mailbox.public()) }),
    );
    m.insert("sent_at".into(), now().into());
    m.insert("body".into(), json!({ "link": link }));
    m.insert("attachments".into(), json!([]));
    let mut h = Value::Object(m);
    message::sign(&mut h, &p.signer);
    h
}

fn zat(zec: &str) -> Result<u64, String> {
    let v: f64 = zec
        .parse()
        .map_err(|_| format!("not an amount in ZEC: {zec}"))?;
    if !(v.is_finite() && v >= 0.0) {
        return Err(format!("not an amount in ZEC: {zec}"));
    }
    Ok((v * 1e8).round() as u64)
}

fn directory_cli(args: &[String]) -> Result<(), String> {
    let path = dir().join("directory.json");
    let mut list: Vec<directory::Listing> = match fs::read(&path) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))?,
        Err(_) => Vec::new(),
    };
    let save = |list: &Vec<directory::Listing>| {
        fs::write(&path, serde_json::to_vec_pretty(list).unwrap()).map_err(|e| e.to_string())
    };
    match args.first().map(String::as_str) {
        Some("add") => {
            let [_, name, contact, pk, min, max, tenor, kyc] = args else {
                return Err("usage: jitsuin-node provider directory add <name> <contact_card> <financier_pk> <min_zec> <max_zec> <max_tenor_days> <buyer_kyc yes|no>".into());
            };
            let mandate = directory::Mandate {
                min_zat: zat(min)?,
                max_zat: zat(max)?,
                max_tenor_days: tenor.parse().map_err(|_| "the longest tenor is a number of days")?,
                buyer_kyc: kyc == "yes",
            };
            let l = directory::listing(name, contact, pk, mandate, now())?;
            directory::upsert(&mut list, l)?;
            save(&list)?;
            println!("listed; {} financier(s) in the directory", list.len());
            Ok(())
        }
        Some("remove") => {
            let Some(pk) = args.get(1) else {
                return Err("usage: jitsuin-node provider directory remove <financier_pk>".into());
            };
            let before = list.len();
            list.retain(|l| l.financier_pk != pk.to_ascii_lowercase());
            save(&list)?;
            println!("{} removed; {} left", before - list.len(), list.len());
            Ok(())
        }
        Some("list") => {
            for l in &list {
                println!("{}  {}  {}-{} zat, ≤{} days, KYC {}", l.financier_pk, l.name, l.mandate.min_zat, l.mandate.max_zat, l.mandate.max_tenor_days, if l.mandate.buyer_kyc { "yes" } else { "no" });
            }
            println!("{} financier(s)", list.len());
            Ok(())
        }
        Some("publish") => {
            let Some(out) = args.get(1) else {
                return Err("usage: jitsuin-node provider directory publish <out.json>".into());
            };
            let p = load(false)?;
            let d = directory::signed(&list, &p.signer, now());
            // the same check the web app makes, before the file leaves this machine
            if !directory::verify(&d, &hex(&p.signer.verifying_key().to_bytes())) {
                return Err("the signed directory does not verify".into());
            }
            fs::write(out, serde_json::to_vec(&d).unwrap()).map_err(|e| e.to_string())?;
            println!("published {} financier(s) to {out}", list.len());
            Ok(())
        }
        _ => Err("usage: jitsuin-node provider directory add … | remove <financier_pk> | list | publish <out.json> (listings from nodes: provider listings | provider accept <relay_id>)".into()),
    }
}

/// The `financier.listing` messages in the provider mailbox (HNK-30.T19).
async fn listings_cli(args: &[String]) -> Result<(), String> {
    let p = load(false)?;
    let r = relay()?;
    r.ensure_mailbox(&p.mailbox)
        .await
        .map_err(|e| e.to_string())?;
    let (got, _, token) = r.receive(&p.mailbox).await.map_err(|e| e.to_string())?;
    let mine: Vec<_> = got
        .iter()
        .filter(|m| m.message.header["type"] == "financier.listing")
        .collect();
    match args.first().map(String::as_str) {
        Some("listings") => {
            for m in &mine {
                match directory::read_listing(&m.message.header, now()) {
                    Ok(l) => println!(
                        "{}  {}  {}  {}-{} zat, ≤{} days, KYC {}",
                        m.relay_id,
                        l.name,
                        l.financier_pk,
                        l.mandate.min_zat,
                        l.mandate.max_zat,
                        l.mandate.max_tenor_days,
                        if l.mandate.buyer_kyc { "yes" } else { "no" }
                    ),
                    Err(e) => println!("{}  refused: {e}", m.relay_id),
                }
            }
            println!("{} listing(s)", mine.len());
            Ok(())
        }
        Some("accept") => {
            let Some(id) = args.get(1) else {
                return Err("usage: jitsuin-node provider accept <relay_id>".into());
            };
            let m = mine
                .iter()
                .find(|m| &m.relay_id == id)
                .ok_or("no listing with that id")?;
            let l = directory::read_listing(&m.message.header, now())?;
            let path = dir().join("directory.json");
            let mut list: Vec<directory::Listing> = fs::read(&path)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
            let name = l.name.clone();
            directory::upsert(&mut list, l)?;
            fs::write(&path, serde_json::to_vec_pretty(&list).unwrap())
                .map_err(|e| e.to_string())?;
            r.remove(&p.mailbox, id, &token)
                .await
                .map_err(|e| e.to_string())?;
            println!("{name} listed; run `provider directory publish` to publish");
            Ok(())
        }
        _ => unreachable!(),
    }
}

pub async fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("init") => {
            let p = load(true)?;
            relay()?.ensure_mailbox(&p.mailbox).await.map_err(|e| e.to_string())?;
            println!("provider mailbox_pk {}", hex(&p.mailbox.public()));
            println!("provider signer_pk  {}", hex(&p.signer.verifying_key().to_bytes()));
            println!("Put both in jitsuinfi-frontend src/lib/provider.ts.");
            Ok(())
        }
        Some("inbox") => {
            let p = load(false)?;
            let r = relay()?;
            r.ensure_mailbox(&p.mailbox).await.map_err(|e| e.to_string())?;
            let (got, refused, _) = r.receive(&p.mailbox).await.map_err(|e| e.to_string())?;
            for m in got.iter().filter(|m| m.message.header["type"] == "financier.apply") {
                let h = &m.message.header;
                println!("{}  {}", m.relay_id, m.received_at);
                println!("  name    {}", h["body"]["name"].as_str().unwrap_or("?"));
                println!("  contact {}", h["body"]["contact"].as_str().unwrap_or("?"));
                if let Some(n) = h["body"]["note"].as_str() {
                    println!("  note    {n}");
                }
                println!("  reply   {}", h["from"]["mailbox_pk"].as_str().unwrap_or("?"));
                if h["body"]["list"] == true {
                    println!("  listed  yes: wants to be in the financier directory");
                }
            }
            println!("{} application(s), {refused} refused", got.iter().filter(|m| m.message.header["type"] == "financier.apply").count());
            Ok(())
        }
        Some("invite") => {
            let (Some(to), Some(link)) = (args.get(1), args.get(2)) else {
                return Err("usage: jitsuin-node provider invite <reply_mailbox_pk> <invite_link>".into());
            };
            if !link.starts_with("https://") || !link.contains("/console/pair#") {
                return Err("the invite link must be https://<console>/console/pair#<code>".into());
            }
            let to = unhex::<32>(to)?;
            let p = load(false)?;
            let h = invite_header(&p, &to, link);
            let bytes = message::encode(&h, &[])?;
            let id = relay()?.send(&to, &bytes).await.map_err(|e| e.to_string())?;
            println!("invite sent ({id})");
            Ok(())
        }
        Some("remove") => {
            let Some(id) = args.get(1) else {
                return Err("usage: jitsuin-node provider remove <relay_id>".into());
            };
            let p = load(false)?;
            let r = relay()?;
            let token = r.read_token(&p.mailbox).await.map_err(|e| e.to_string())?;
            r.remove(&p.mailbox, id, &token).await.map_err(|e| e.to_string())?;
            println!("removed");
            Ok(())
        }
        Some("directory") => directory_cli(&args[1..]),
        Some("listings") | Some("accept") => listings_cli(args).await,
        _ => Err("usage: jitsuin-node provider init | inbox | invite <reply_mailbox_pk> <link> | remove <relay_id> | directory …".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_invite_is_signed_by_the_provider_and_addressed_to_the_applicant() {
        let p = Provider {
            signer: SigningKey::from_bytes(&[3; 32]),
            mailbox: MailboxKeys::from_prf(&[4; 32]),
        };
        let applicant = MailboxKeys::from_prf(&[5; 32]);
        let h = invite_header(
            &p,
            &applicant.public(),
            "https://jitsuinfi-console.vercel.app/console/pair#ABCD-EFGH-IJKL-MNOP",
        );
        assert!(message::verify(
            &h,
            Some(&hex(&p.signer.verifying_key().to_bytes()))
        ));
        let m = message::decode(&message::encode(&h, &[]).unwrap(), &hex(&applicant.id())).unwrap();
        assert_eq!(
            m.header["body"]["link"],
            "https://jitsuinfi-console.vercel.app/console/pair#ABCD-EFGH-IJKL-MNOP"
        );
    }
}
