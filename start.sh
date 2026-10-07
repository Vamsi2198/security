#!/bin/sh
# Start all three processes; the proxy (public entrypoint) runs in the foreground.
set -e

echo "[start] launching Portkey gateway on 127.0.0.1:8787 ..."
node /app/gw/node_modules/@portkey-ai/gateway/build/start-server.js &

echo "[start] launching mock LLM (:9100) + safety webhook (:9200) ..."
python3 /app/mock_services.py &

# Wait for the gateway to accept connections before opening the proxy
i=0
until python3 -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',8787))==0 else 1)"; do
  i=$((i+1)); [ "$i" -gt 60 ] && echo "[start] gateway never came up" && exit 1
  sleep 1
done
echo "[start] gateway healthy"

echo "[start] launching policy proxy on ${BIND:-0.0.0.0}:${PORT:-10000} ..."
exec python3 /app/policy_proxy.py
