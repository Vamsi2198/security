#!/usr/bin/env bash
# Render start command: boot the Portkey OSS gateway (Node) in the
# background, wait for it, then serve the demo page on $PORT.
set -e
cd "$(dirname "$0")"

TRUSTED_CUSTOM_HOSTS="127.0.0.1,localhost" \
  node node_modules/@portkey-ai/gateway/build/start-server.js \
  > gateway.log 2>&1 &

# Give the gateway up to 60s to come up (usually ~2s).
for _ in $(seq 1 60); do
  if curl -s -o /dev/null http://127.0.0.1:8787; then break; fi
  sleep 1
done

exec python app.py
