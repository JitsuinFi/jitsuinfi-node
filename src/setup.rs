//! Testnet node setup (HNK-26.T1, BL-D21-14, BL-D0-02): idempotent, run at every start. On the
//! first start it makes the node master key, the financier's spending wallet (zcash-devtool,
//! mnemonic encrypted to an age identity it generates) and the watch-only board wallet from the
//! public board UFVK. Later starts only load them. Nothing secret is printed.

use std::path::{Path, PathBuf};
use std::process::Command;

use jitsuin_wallet::Devtool;

use crate::config::Config;
use crate::keys::NodeKeys;

/// The wallets are used by the deal API (HNK-26.T5 onward); setup only makes and checks them.
#[allow(dead_code)]
pub struct Node {
    pub keys: NodeKeys,
    pub wallet: Devtool,
    pub board_watch: Devtool,
    pub wallet_address: String,
}

pub struct Paths {
    pub key: PathBuf,
    pub wallet: PathBuf,
    pub identity: PathBuf,
    pub board: PathBuf,
}

impl Paths {
    pub fn new(data: &Path) -> Self {
        Paths {
            key: data.join("node.key"),
            wallet: data.join("wallet"),
            identity: data.join("wallet.age"),
            board: data.join("board-watch"),
        }
    }
}

fn devtool_init(cfg: &Config, p: &Paths) -> Result<(), String> {
    let out = Command::new(&cfg.devtool)
        .arg("wallet")
        .arg("-w")
        .arg(&p.wallet)
        .args([
            "init",
            "--name",
            &cfg.wallet_name,
            "--network",
            &cfg.network,
            "--identity",
        ])
        .arg(&p.identity)
        .output()
        .map_err(|e| format!("cannot run zcash-devtool ({}): {e}", cfg.devtool.display()))?;
    if !out.status.success() {
        // stderr may name paths, never the mnemonic (it is written encrypted to the wallet)
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "wallet init failed: {}",
            err.lines()
                .rfind(|l| l.contains("Error"))
                .unwrap_or("non-zero exit")
                .trim()
        ));
    }
    Ok(())
}

/// Loads or creates everything the node needs. Returns the node and what was created now.
pub fn setup(cfg: &Config) -> Result<(Node, Vec<&'static str>), String> {
    std::fs::create_dir_all(&cfg.data_dir)
        .map_err(|e| format!("cannot create {}: {e}", cfg.data_dir.display()))?;
    let p = Paths::new(&cfg.data_dir);
    let mut made = Vec::new();

    let (keys, new_key) = NodeKeys::load_or_create(&p.key).map_err(|e| format!("node key: {e}"))?;
    if new_key {
        made.push("node key");
    }
    if !p.wallet.join("data.sqlite").exists() && !p.wallet.exists() {
        devtool_init(cfg, &p)?;
        made.push("financier wallet");
    }
    // the age identity decrypts the wallet mnemonic: owner-only, whoever created it
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if p.identity.exists() {
            std::fs::set_permissions(&p.identity, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("wallet identity: {e}"))?;
        }
    }
    let board_watch = Devtool::new(&cfg.devtool, &p.board);
    if !p.board.exists() {
        board_watch
            .init_fvk("TES-board-watch", &cfg.board_ufvk, cfg.board_birthday)
            .map_err(|e| format!("board watch wallet: {e}"))?;
        made.push("board watch wallet");
    }
    let wallet = Devtool::new(&cfg.devtool, &p.wallet).with_identity(&p.identity);
    let wallet_address = wallet
        .default_address()
        .map_err(|e| format!("wallet address: {e}"))?;
    Ok((
        Node {
            keys,
            wallet,
            board_watch,
            wallet_address,
        },
        made,
    ))
}
