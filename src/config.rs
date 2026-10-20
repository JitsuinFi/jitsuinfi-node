//! Node settings from the environment (Railway variables; a shell locally). Nothing secret here:
//! the keys live in the data volume.

use std::path::PathBuf;

#[derive(Debug, Clone)]
#[allow(dead_code)] // lightwalletd serves the deal API (next task)
pub struct Config {
    pub port: u16,
    /// The Railway Volume (or a local folder): node.key, the wallet, its age identity, the board.
    pub data_dir: PathBuf,
    pub devtool: PathBuf,
    /// "test" or "main"; the node refuses to mix networks with the board key.
    pub network: String,
    pub lightwalletd: String,
    /// The public board viewing key and its first block (jitsuinfi-zcash examples/testnet).
    pub board_ufvk: String,
    pub board_birthday: u32,
    /// The relay (jitsuinfi-backend), for the financier's mailbox.
    pub relay_url: String,
    /// A name for the wallet account (test data starts with TES-).
    pub wallet_name: String,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let network = var("NETWORK").unwrap_or_else(|| "test".into());
        if network != "test" && network != "main" {
            return Err("NETWORK must be \"test\" or \"main\"".into());
        }
        let board_ufvk =
            var("BOARD_UFVK").ok_or("BOARD_UFVK is not set (the public board viewing key)")?;
        let ufvk_net = if board_ufvk.starts_with("uviewtest1") {
            "test"
        } else if board_ufvk.starts_with("uview1") {
            "main"
        } else {
            return Err("BOARD_UFVK is not a unified full viewing key".into());
        };
        if ufvk_net != network {
            return Err(format!(
                "BOARD_UFVK is a {ufvk_net}net key but NETWORK is {network}"
            ));
        }
        Ok(Config {
            port: var("PORT")
                .map(|p| p.parse().map_err(|_| "PORT must be a number"))
                .transpose()?
                .unwrap_or(8788),
            data_dir: var("DATA_DIR").unwrap_or_else(|| "/data".into()).into(),
            devtool: var("ZCASH_DEVTOOL")
                .unwrap_or_else(|| "zcash-devtool".into())
                .into(),
            lightwalletd: var("LIGHTWALLETD").unwrap_or_else(|| {
                if network == "test" {
                    "https://testnet.zec.rocks:443".into()
                } else {
                    "https://zec.rocks:443".into()
                }
            }),
            network,
            board_ufvk,
            board_birthday: var("BOARD_BIRTHDAY")
                .ok_or("BOARD_BIRTHDAY is not set")?
                .parse()
                .map_err(|_| "BOARD_BIRTHDAY must be a block height")?,
            relay_url: var("RELAY_URL")
                .unwrap_or_else(|| "https://relay-production-27dc.up.railway.app".into()),
            wallet_name: var("WALLET_NAME").unwrap_or_else(|| "TES-financier-node".into()),
        })
    }
}
