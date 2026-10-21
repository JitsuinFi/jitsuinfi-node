#!/bin/sh
# Uploads deploy/ to one Railway service, waiting out a Railway outage (2026-10-21: "Deploys have
# been paused temporarily" for many hours). Retries every 10 minutes for up to 5 hours while
# Railway refuses for a reason of its own; any other failure stops at once.
set -u
service="$1"
for i in $(seq 1 30); do
  if out=$(npx --yes @railway/cli@5.71.0 up deploy --path-as-root --no-gitignore --service "$service" --ci --detach 2>&1); then
    echo "$out"
    exit 0
  fi
  echo "$out" | tail -n 3
  if ! echo "$out" | grep -qiE "paused|unavailable|timed out|try again|502|503|504"; then
    exit 1
  fi
  echo "Railway is not taking deploys; retry $i/30 in 10 minutes"
  sleep 600
done
exit 1
