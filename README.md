# jitsuinfi-node

A **JitsuinFi** financier's node (HNK-26): its keys, its Zcash wallet, the board it checks, its relay mailbox, its console and, next, the deal API. Built on the `jitsuin-*` crates of `jitsuinfi-zcash`, pinned to a commit.

## Keys
All in the data volume (`DATA_DIR`, `/data` on Railway), never in the repo, the image, a log or an API:
- `node.key` (32 random bytes, mode 0600): the financier's Ed25519 key and its mailbox key are derived from it (BLAKE2b, personalizations `JitsuinNodeFin__`, `JitsuinNodeMbox_`).
- `wallet/` + `wallet.age` (0600): the zcash-devtool spending wallet, its mnemonic encrypted to the age identity.
- `board-watch/`: watch-only wallet of the public board UFVK.
- `pairing.json` (0600): the SHA-256 of a waiting pairing code, while one waits.
- `console-credentials.json` (0600, D9): the console passkeys (public keys only).

`jitsuin-node setup` makes what is missing (HNK-26.T1) and prints only public values; `serve` runs setup, registers the financier mailbox at the relay (HNK-26.T4), then serves `GET /node/health`, `GET /node/info` (financier key, mailbox id, wallet address, contact card) and the console. `jitsuin-node inbox` lists the messages in the mailbox.

## Console pairing and sign-in (HNK-26.T2, T3)
1. Set `NODE_ORIGIN` to the node's own HTTPS origin (the Railway domain); its host is the passkey `rp.id`.
2. On the node, run `jitsuin-node pair` (Railway: `railway ssh --service financier-node jitsuin-node pair`). It prints a one-time code, valid for 15 minutes; only its hash is stored, never a log line.
3. Open `<NODE_ORIGIN>/console/pair`, type the code and create the passkey. The node verifies the attestation (challenge, origin, `rpIdHash`, user verification) and keeps the credential.

Then sign in at `<NODE_ORIGIN>/console/` (HNK-26.T3): a one-time challenge (2 minutes), an assertion checked for origin, `rpIdHash`, user verification, signature and counter, then an 8-hour session in a `__Host-jitsuin_console` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`). The node keeps only the SHA-256 of session tokens, in memory.

Signed in, the console lists the financier mailbox through the node (HNK-26.T4): `GET /node/mail` opens the sealed messages with the node's mailbox key and returns their headers; `GET /node/mail/{id}/attachments/{i}` returns a PDF; `DELETE /node/mail/{id}` removes a message at the relay. All three need the session cookie; the removal also needs the console's `Origin`. The browser never holds the mailbox key.

Every advance needs a passkey approval of that payment (HNK-26.T15): `POST /node/console/approve/start` with the intent (N, amount, address) and `/finish` with a fresh assertion give a one-time approval, valid 5 minutes for that payment only; the payment gate (`pay::advance`) uses it up before `Financier::pay_advance`. A session cookie alone cannot pay.

A code is used up on its first correct try and dropped after five wrong ones. The console's POSTs must carry the console's own `Origin`; every response has a same-origin CSP and `frame-ancestors 'none'`.

## Settings
| Variable | Value |
|---|---|
| `BOARD_UFVK` | the public board key (`jitsuinfi-zcash/examples/testnet/board-ufvk.txt`) |
| `BOARD_BIRTHDAY` | `4508703` |
| `NETWORK` | `test` (default) |
| `DATA_DIR` | `/data` (default) |
| `ZCASH_DEVTOOL` | path of zcash-devtool (`/usr/local/bin/zcash-devtool` in the image) |
| `RELAY_URL` | relay base URL (default: the Railway relay) |
| `NODE_ORIGIN` | the console's origin, e.g. `https://financier-node-production.up.railway.app`; without it the console is off |
| `PORT` | set by Railway |

## Deploy
CI builds `jitsuin-node` and zcash-devtool on ubuntu-24.04 (zcash-devtool cached by revision) and runs `railway up deploy --service financier-node`: `deploy/Dockerfile` only copies the two binaries, so Railway never compiles. Secrets: `ZCASH_DEPLOY_KEY` (read-only deploy key of `jitsuinfi-zcash`), `RAILWAY_TOKEN` (project token of `jitsuinfi-relay`). The service mounts a Railway Volume at `/data`.

Status: in development for ZECATHON 2026, on Zcash testnet. The spending key is a hot wallet on the server: fine for small testnet amounts; a production financier runs its node on its own infrastructure.
