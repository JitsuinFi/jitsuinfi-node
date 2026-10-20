# jitsuinfi-node

A **JitsuinFi** financier's node (HNK-26): its keys, its Zcash wallet, the board it checks, its relay mailbox and, next, the deal API and console. Built on the `jitsuin-*` crates of `jitsuinfi-zcash`, pinned to a commit.

## Keys
All in the data volume (`DATA_DIR`, `/data` on Railway), never in the repo, the image, a log or an API:
- `node.key` (32 random bytes, mode 0600): the financier's Ed25519 key and its mailbox key are derived from it (BLAKE2b, personalizations `JitsuinNodeFin__`, `JitsuinNodeMbox_`).
- `wallet/` + `wallet.age` (0600): the zcash-devtool spending wallet, its mnemonic encrypted to the age identity.
- `board-watch/`: watch-only wallet of the public board UFVK.

`jitsuin-node setup` makes what is missing (HNK-26.T1) and prints only public values; `serve` runs setup, then serves `GET /node/health` and `GET /node/info` (financier key, mailbox id, wallet address).

## Settings
| Variable | Value |
|---|---|
| `BOARD_UFVK` | the public board key (`jitsuinfi-zcash/examples/testnet/board-ufvk.txt`) |
| `BOARD_BIRTHDAY` | `4508703` |
| `NETWORK` | `test` (default) |
| `DATA_DIR` | `/data` (default) |
| `ZCASH_DEVTOOL` | path of zcash-devtool (`/usr/local/bin/zcash-devtool` in the image) |
| `RELAY_URL` | relay base URL (default: the Railway relay) |
| `PORT` | set by Railway |

## Deploy
CI builds `jitsuin-node` and zcash-devtool on ubuntu-24.04 (zcash-devtool cached by revision) and runs `railway up deploy --service financier-node`: `deploy/Dockerfile` only copies the two binaries, so Railway never compiles. Secrets: `ZCASH_DEPLOY_KEY` (read-only deploy key of `jitsuinfi-zcash`), `RAILWAY_TOKEN` (project token of `jitsuinfi-relay`). The service mounts a Railway Volume at `/data`.

Status: in development for ZECATHON 2026, on Zcash testnet. The spending key is a hot wallet on the server: fine for small testnet amounts; a production financier runs its node on its own infrastructure.
