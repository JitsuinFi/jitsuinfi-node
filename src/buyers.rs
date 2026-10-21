//! The financier's registry of buyers it knows from KYC (HNK-26.T7, BL-D26-05): each entry is a
//! buyer's `identity_pk` (shown in the buyer's app) with the operator's own label. A buyer
//! history (`history.chain`) whose identity key is not in the registry is flagged in the console,
//! and the history check (HNK-26.T8) uses the same registry.
//!
//! Kept in `buyers.json` in the volume, owner-only, written whole through a temporary file.

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::message::{hex, unhex};

pub const FILE: &str = "buyers.json";
/// Enough for a financier's book of buyers; keeps the file and the console list small.
pub const MAX_BUYERS: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Buyer {
    pub identity_pk: String,
    /// The operator's note: the company name or its KYC reference. Stays on this node.
    pub label: String,
    /// Seconds since the Unix epoch.
    pub added_at: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RegistryError {
    Input(&'static str),
    Full,
    Io(String),
}

pub struct Registry {
    path: PathBuf,
    buyers: RwLock<Vec<Buyer>>,
}

/// A label: printable, at most 80 characters, trimmed.
fn clean_label(l: &str) -> Option<String> {
    let l: String = l.chars().filter(|c| !c.is_control()).take(80).collect();
    let l = l.trim().to_string();
    (!l.is_empty()).then_some(l)
}

impl Registry {
    /// Loads the registry from `data_dir`; a missing file is an empty registry.
    pub fn load(data_dir: &Path) -> Result<Self, String> {
        let path = data_dir.join(FILE);
        let buyers = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{FILE}: {e}"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(format!("{FILE}: {e}")),
        };
        Ok(Registry {
            path,
            buyers: RwLock::new(buyers),
        })
    }

    pub fn list(&self) -> Vec<Buyer> {
        self.buyers.read().unwrap().clone()
    }

    /// The entry for an identity key (hex), if the buyer is registered.
    pub fn get(&self, identity_pk: &str) -> Option<Buyer> {
        let pk = identity_pk.to_ascii_lowercase();
        self.buyers
            .read()
            .unwrap()
            .iter()
            .find(|b| b.identity_pk == pk)
            .cloned()
    }

    /// Adds a buyer, or renames it when the key is registered already.
    pub fn add(&self, identity_pk: &str, label: &str, now: u64) -> Result<Buyer, RegistryError> {
        let pk = identity_pk.trim().to_ascii_lowercase();
        let key = unhex::<32>(&pk)
            .map_err(|_| RegistryError::Input("the identity key must be 64 hex characters"))?;
        ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map_err(|_| RegistryError::Input("this is not a valid identity key"))?;
        let label = clean_label(label).ok_or(RegistryError::Input(
            "give the buyer a name or KYC reference",
        ))?;
        let mut buyers = self.buyers.write().unwrap();
        let mut next = buyers.clone();
        let entry = match next.iter_mut().find(|b| b.identity_pk == pk) {
            Some(b) => {
                b.label = label;
                b.clone()
            }
            None => {
                if next.len() >= MAX_BUYERS {
                    return Err(RegistryError::Full);
                }
                let b = Buyer {
                    identity_pk: hex(&key),
                    label,
                    added_at: now,
                };
                next.push(b.clone());
                b
            }
        };
        self.save(&next)?;
        *buyers = next;
        Ok(entry)
    }

    /// Removes a buyer; false when the key was not registered.
    pub fn remove(&self, identity_pk: &str) -> Result<bool, RegistryError> {
        let pk = identity_pk.to_ascii_lowercase();
        let mut buyers = self.buyers.write().unwrap();
        let next: Vec<Buyer> = buyers
            .iter()
            .filter(|b| b.identity_pk != pk)
            .cloned()
            .collect();
        if next.len() == buyers.len() {
            return Ok(false);
        }
        self.save(&next)?;
        *buyers = next;
        Ok(true)
    }

    fn save(&self, buyers: &[Buyer]) -> Result<(), RegistryError> {
        use std::io::Write;
        let io = |e: std::io::Error| RegistryError::Io(e.to_string());
        let tmp = self.path.with_extension("json.tmp");
        let mut f = std::fs::OpenOptions::new();
        f.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut f, 0o600);
        let mut file = f.open(&tmp).map_err(io)?;
        file.write_all(&serde_json::to_vec_pretty(buyers).unwrap())
            .and_then(|_| file.sync_all())
            .map_err(io)?;
        std::fs::rename(&tmp, &self.path).map_err(io)
    }

    /// What the console shows next to a `history.chain`: whether its identity key is registered.
    pub fn flag(&self, header: &Value) -> Value {
        match header["body"]["identity_pk"].as_str() {
            None => json!({ "registered": false, "missing": true }),
            Some(pk) => match self.get(pk) {
                Some(b) => json!({ "registered": true, "label": b.label }),
                None => json!({ "registered": false }),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("jitsuin-buyers-{}", crate::message::random_id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn pk(b: u8) -> String {
        hex(&ed25519_dalek::SigningKey::from_bytes(&[b; 32])
            .verifying_key()
            .to_bytes())
    }

    #[test]
    fn buyers_are_added_renamed_removed_and_kept_on_disk() {
        let d = dir();
        let r = Registry::load(&d).unwrap();
        assert!(r.list().is_empty());
        r.add(&pk(1), "  PT Sakura Niaga ", 10).unwrap();
        r.add(&pk(2).to_uppercase(), "KYC-0042", 11).unwrap();
        assert_eq!(r.add(&pk(1), "PT Sakura", 12).unwrap().added_at, 10);
        let again = Registry::load(&d).unwrap();
        assert_eq!(again.list().len(), 2);
        assert_eq!(again.get(&pk(1)).unwrap().label, "PT Sakura");
        assert_eq!(again.get(&pk(2)).unwrap().identity_pk, pk(2));
        assert!(again.remove(&pk(1)).unwrap());
        assert!(!again.remove(&pk(1)).unwrap());
        assert_eq!(Registry::load(&d).unwrap().list().len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn bad_keys_and_empty_labels_are_refused() {
        let d = dir();
        let r = Registry::load(&d).unwrap();
        assert!(matches!(r.add("abc", "x", 1), Err(RegistryError::Input(_))));
        assert!(matches!(
            r.add(&pk(1), "   ", 1),
            Err(RegistryError::Input(_))
        ));
        assert!(r.list().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn chains_with_unregistered_identity_keys_are_flagged() {
        let d = dir();
        let r = Registry::load(&d).unwrap();
        r.add(&pk(1), "PT Sakura", 1).unwrap();
        let chain = |id: Option<String>| json!({ "type": "history.chain", "body": { "certs": ["x"], "identity_pk": id } });
        assert_eq!(
            r.flag(&chain(Some(pk(1)))),
            json!({ "registered": true, "label": "PT Sakura" })
        );
        assert_eq!(r.flag(&chain(Some(pk(3)))), json!({ "registered": false }));
        assert_eq!(
            r.flag(&json!({ "type": "history.chain", "body": { "certs": ["x"] } })),
            json!({ "registered": false, "missing": true })
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
