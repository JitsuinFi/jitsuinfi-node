#!/bin/sh
# Uploads deploy/ to one Railway service. While Railway refuses for a reason of its own (2026-10-21
# and 2026-10-22: "Deploys have been paused" for many hours) it tries once more after a minute and
# then fails: waiting inside the runner is billed by the minute, and on 2026-10-22 it used up the
# account's Actions minutes. The "retry deploy" workflow re-runs the failed job later instead.
set -u
service="$1"
for i in 1 2; do
  if out=$(npx --yes @railway/cli@5.71.0 up deploy --path-as-root --no-gitignore --service "$service" --ci --detach 2>&1); then
    echo "$out"
    exit 0
  fi
  echo "$out" | tail -n 3
  if ! echo "$out" | grep -qiE "paused|unavailable|timed out|try again|502|503|504"; then
    exit 1
  fi
  [ "$i" = 2 ] && break
  echo "Railway is not taking deploys; one more try in a minute"
  sleep 60
done
exit 1
