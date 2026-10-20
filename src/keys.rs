//! The node's own keys (HNK-26.T1), all from one 32-byte master secret kept in the data volume
//! (`node.key`, mode 0600). It never leaves the node: not in the repo, the image, a log or an API.
//!
//! - financier key (Ed25519): `BLAKE2b-256(key = master, personalization = "JitsuinNodeFin__",
//!   "financier")`. Its public key is the financier's identity in commitments, letters, receipts.
//! - mailbox seed: `BLAKE2b-256(key = master, personalization = "JitsuinNodeMbox_", "mailbox")`,
//!   used as the browser uses its inbox PRF output (`jitsuin_core::mailbox::MailboxKeys::from_prf`).
//!
//! The Zcash spending key is separate: the zcash-devtool wallet keeps its own seed, encrypted to
//! the age identity in the same volume.

use std::fs;
use std::io::Write;
use std::path::Path;

use blake2b_simd::Params;
use ed25519_dalek::SigningKey;
use jitsuin_core::mailbox::MailboxKeys;
use rand::RngCore;

pub struct NodeKeys {
    master: [u8; 32],
}

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

impl NodeKeys {
    /// Loads `node.key`, or makes it on first start. Refuses a file of the wrong size.
    pub fn load_or_create(path: &Path) -> std::io::Result<(Self, bool)> {
        if path.exists() {
            let bytes = fs::read(path)?;
            let master: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                std::io::Error::other(format!("{} is not 32 bytes", path.display()))
            })?;
            return Ok((NodeKeys { master }, false));
        }
        let mut master = [0u8; 32];
        rand::rng().fill_bytes(&mut master);
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path)?.write_all(&master)?;
        Ok((NodeKeys { master }, true))
    }

    #[cfg(test)]
    pub fn from_master(master: [u8; 32]) -> Self {
        NodeKeys { master }
    }

    pub fn financier(&self) -> SigningKey {
        SigningKey::from_bytes(&derive(&self.master, b"JitsuinNodeFin__", b"financier"))
    }

    pub fn mailbox(&self) -> MailboxKeys {
        let mut seed = derive(&self.master, b"JitsuinNodeMbox_", b"mailbox");
        let k = MailboxKeys::from_prf(&seed);
        seed = [0u8; 32];
        std::hint::black_box(&seed);
        k
    }
}

impl Drop for NodeKeys {
    fn drop(&mut self) {
        self.master = [0u8; 32];
        std::hint::black_box(&self.master);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_stable_and_separate() {
        let a = NodeKeys::from_master([7; 32]);
        let b = NodeKeys::from_master([7; 32]);
        assert_eq!(a.financier().verifying_key(), b.financier().verifying_key());
        assert_eq!(a.mailbox().public(), b.mailbox().public());
        assert_ne!(
            a.financier().verifying_key().to_bytes(),
            a.mailbox().public()
        );
        assert_ne!(
            a.financier().verifying_key(),
            NodeKeys::from_master([8; 32]).financier().verifying_key()
        );
    }

    #[test]
    fn the_master_file_is_made_once_and_private() {
        let dir = std::env::temp_dir().join(format!("jitsuin-node-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("node.key");
        let (k1, made) = NodeKeys::load_or_create(&p).unwrap();
        assert!(made);
        let (k2, made) = NodeKeys::load_or_create(&p).unwrap();
        assert!(!made);
        assert_eq!(
            k1.financier().verifying_key(),
            k2.financier().verifying_key()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::write(&p, b"short").unwrap();
        assert!(NodeKeys::load_or_create(&p).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
