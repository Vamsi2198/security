# Risk-Gate demo — single-service image for Render (or any Docker host).
# Bundles: Portkey OSS gateway (Node) + mock LLM/webhook (Python) + policy proxy.
FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Gateway (Node) — installed at build time, runs on 127.0.0.1:8787 inside the container
RUN mkdir gw && cd gw && npm init -y >/dev/null \
    && npm install --ignore-scripts @portkey-ai/gateway

# Demo services (Python, stdlib only — no pip installs needed)
COPY mock_services.py policy_engine.py policy_proxy.py human_review.json ./

# Pre-generate the enforcement store so the image is self-contained
RUN python3 policy_engine.py

COPY start.sh ./
RUN chmod +x start.sh

ENV TRUSTED_CUSTOM_HOSTS="127.0.0.1,localhost"
ENV BIND="0.0.0.0"
# PORT is injected by Render (default 10000). DEMO_TOKEN must be set in the
# Render dashboard — never hardcode it here.

EXPOSE 10000

CMD ["./start.sh"]
