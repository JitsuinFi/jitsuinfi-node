#!/bin/sh
# Provider runbook (HNK-26.T25, D-46 B): make a node for an approved financier application.
#   scripts/provision-node.sh <service-name> "<financier display name>" <reply_mailbox_pk>
# Needs the Railway CLI logged in to the jitsuinfi-relay project, and the provider key
# (~/.jitsuin-provider, made by `jitsuin-node provider init`). Prints nothing secret except the
# invite, which goes to the applicant sealed and signed.
set -eu
SVC="$1"; NAME="$2"; REPLY="$3"
CONSOLE_HOST="${CONSOLE_HOST:-jitsuinfi-console-$SVC.vercel.app}"
UFVK="$(tr -d '\n' < "$(dirname "$0")/../../jitsuinfi-zcash/examples/testnet/board-ufvk.txt")"
CODE="$(openssl rand -hex 10 | tr 'a-f' 'A-F' | sed 's/\(....\)/\1-/g; s/-$//')"

echo "1/5 Railway service $SVC"
railway add --service "$SVC" >/dev/null
railway link --project jitsuinfi-relay --service "$SVC" --environment production >/dev/null
echo "2/5 volume /data"
railway volume add --mount-path /data >/dev/null
echo "3/5 variables (SETUP_CODE is random and never printed here)"
printf '%s' "$CODE" | railway variable set SETUP_CODE --stdin --skip-deploys >/dev/null
railway variable set --skip-deploys NETWORK=test DATA_DIR=/data BOARD_BIRTHDAY=4508703 \
  "WALLET_NAME=TES-$SVC" "FINANCIER_NAME=$NAME" "NODE_ORIGIN=https://$CONSOLE_HOST" "BOARD_UFVK=$UFVK" >/dev/null
echo "4/5 console origin"
echo "    Add a Vercel project for https://$CONSOLE_HOST and a host rule in jitsuinfi-frontend"
echo "    vercel.json forwarding /node/* to https://$(railway domain --json | sed -n 's/.*"https:\/\/\([^"]*\)".*/\1/p')"
echo "    (as for jitsuinfi-console), then add the service to the CI deploy step."
railway link --project jitsuinfi-relay --service financier-node --environment production >/dev/null
echo "5/5 invite to the applicant (sealed to its mailbox, signed by the provider)"
"$(dirname "$0")/../target/release/jitsuin-node" provider invite "$REPLY" "https://$CONSOLE_HOST/console/pair#$CODE"
