# Risk-Gate Demo: When the safety check is too slow, who decides what the gate does?

A 10-minute, fully synthetic, no-API-keys demo for the Prisma AIRS (Portkey)
Principal PM conversation. It proves one observation and one proposal:

- **Observation (verified on the real gateway):** when a custom guardrail
  webhook times out, the request passes by default — `failOnError` is a
  per-check toggle a human must flip by hand.
- **Proposal:** derive the failure mode from the action's **risk tier and
  verification state**, attach it **server-side** with the action parsed
  from the payload itself, and report a **coverage metric** that separates
  human-verified labels from heuristic guesses. Only VERIFIED labels earn
  fail-open; everything else fails closed until a human confirms it.

All data is synthetic. No client work, no real systems, no external calls.

## Architecture

```
caller ──▶ policy_proxy.py (:9300) ──▶ Portkey OSS gateway (:8787) ──▶ mock LLM (:9100)
           parses tool_call from           │ guardrail webhook
           the PAYLOAD, strips              ▼
           client config, attaches      safety webhook (:9200)
           derived tier server-side      (degraded mode: too slow to answer)
```

Two rules make this enforcement rather than convention:

1. **The action comes from the payload, not the caller.** The request body
   carries a structured `tool_call`; the proxy parses it. Caller-supplied
   labels (headers) are hints at most — a mismatch between claim and payload
   is logged as a security signal. In the product, this is the MCP gateway
   reading the `tools/call` name itself.
2. **Only VERIFIED labels change what the gate does.** A heuristic match
   (OBSERVED) never earns fail-open. A delete tool *described* as "fetch
   records" gets an observed tier 1 — and still fails closed during an
   outage, until a human confirms it. Descriptions can lower trust, never
   raise it — and here that's enforced in behavior, not just reported.

The policy matrix:

| Label | Failure mode during a check outage |
|---|---|
| VERIFIED tier 1 (read-only) | fail open |
| VERIFIED tier 2 (internal write) | fail open + audit receipt fired out of band |
| VERIFIED tier 3 (destructive/external) | fail closed |
| OBSERVED (any tier) | fail closed — pending human review |
| UNCLASSIFIED | fail closed |

## What's inside

| File | Role |
|---|---|
| `mock_services.py` | Mock LLM upstream (:9100) + safety webhook (:9200) with a degraded mode |
| `policy_engine.py` | Risk-tier classifier over a synthetic 14-tool inventory; verified/observed/unclassified states; derives gateway configs from (tier, verification); coverage report |
| `policy_proxy.py` | Server-side enforcement point: derives the action from the payload, strips client config, attaches derived guardrails, fires tier-2 audit receipts out of band, logs every decision and every spoof attempt |
| `human_review.json` | The human review queue — the only path from OBSERVED to VERIFIED |
| `run_demo.py` | The four-act demo driver; writes `transcript.txt` |
| `transcript.txt` | Captured output of a real run |
| `Dockerfile`, `start.sh`, `render.yaml` | Single-service deploy packaging (gateway + mocks + proxy in one container) |

## Setup (5 minutes, laptop)

```bash
# 1. Portkey OSS gateway (MIT license)
mkdir gw && cd gw && npm init -y && npm install --ignore-scripts @portkey-ai/gateway

# 2. Start the gateway, allowlisting localhost webhooks (self-hosted requirement)
TRUSTED_CUSTOM_HOSTS="127.0.0.1,localhost" node node_modules/@portkey-ai/gateway/build/start-server.js

# 3. Run the demo (starts the mock services and proxy itself)
python3 run_demo.py
```

## Deploy (Render, one service)

For a live URL a hiring manager can curl. One Docker container bundles the
gateway (internal, `127.0.0.1:8787`), the mock services, and the proxy
(public entrypoint on `$PORT`). The proxy requires a demo token — a missing
or wrong token fails closed with a 401, which is on brand.

```bash
# local build check
docker build -t risk-gate-demo .
docker run -p 10000:10000 -e DEMO_TOKEN=choose-a-token risk-gate-demo
```

On Render: push this folder to a repo, "New → Web Service → Docker" (or use
the included `render.yaml`), set `DEMO_TOKEN` in the dashboard. Health checks
hit `/healthz` (no token required).

Try the deployed demo:

```bash
BASE=https://your-service.onrender.com
TOK=choose-a-token

# verified read-only action rides out the outage  -> 200
curl -i -X POST $BASE/v1/chat/completions -H "x-demo-token: $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"model":"mock-llm","messages":[{"role":"user","content":"run the weekly report"}],
       "tool_call":{"server":"analytics-server","tool":"run_report","arguments":{"report_id":"w1"}}}'

# destructive action, safety check degraded       -> 446
curl -i -X POST $BASE/v1/chat/completions -H "x-demo-token: $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"model":"mock-llm","messages":[{"role":"user","content":"delete customer 4417"}],
       "tool_call":{"server":"crm-server","tool":"delete_customer","arguments":{"customer_id":"4417"}}}'

# no token                                        -> 401
curl -i -X POST $BASE/v1/chat/completions -H 'Content-Type: application/json' -d '{}'
```

The safety webhook is always degraded in this deployment — the outage *is*
the demo scenario. `Dockerfile`, `start.sh`, and `render.yaml` are the only
deploy-specific files; the demo logic is untouched.

**Rather click than curl?** Open `https://your-service.onrender.com/` in a
browser. The proxy serves a guided demo console: the token is built into the
page, five numbered scenario buttons walk the policy (verified read → pass,
verified write → pass + audit receipt, destructive → block, spoofed label →
block, unclassified → block), each shows the derived tier and outcome with a
plain-English "what happened", and the audit trail streams live from
`GET /receipts`. `POST /reset` clears the trail between visitors.

## The four acts

**Act 1 — the gap.** A destructive request goes through the gateway with a
guardrail webhook too slow to answer. The gateway times the check out at
1000ms... and lets the delete through. HTTP 200. Documented behavior:
timeout defaults to `verdict: true`.

**Act 2 — the primitive that exists.** Identical request, identical degraded
webhook, but `failOnError: true`. HTTP 446, blocked. The docs ship this
toggle — so the pitch is never "add fail-closed." It's that the decision
lives as a per-check boolean nobody governs.

**Act 3 — the proposal.** The engine classified a synthetic 14-tool
inventory; the proxy parses each action from the payload's `tool_call` and
attaches the derived guardrail server-side. With the webhook still degraded:
a VERIFIED read-only report passes (200), a VERIFIED internal Slack post
passes in 0.01s with the audit receipt fired out of band, a VERIFIED
destructive delete fails shut (446).

**Act 4 — the hostile caller, two ways.**
*4a, label spoofing:* the payload is a delete but the caller labels it a
read-only report. The proxy derives the action from the payload, logs the
`LABEL_MISMATCH`, blocks (446). *4b, config injection:* the caller attaches
its own fail-open config; the proxy strips it, blocks (446). Both attempts
appear in the audit trail.

**Coverage report.** `verified: 5/14 (36%)  observed: 8/14  unclassified: 1/14`.
Heuristic labels are OBSERVED — and they fail closed. Only human-confirmed
VERIFIED labels earn availability. The metric and the behavior are the same
rule: nobody's guess rides out an outage.

## Talking points while it runs

- "Enforcement today is mapped by hand to scope — org, workspace, server,
  tool. Nothing maps it to what an action *does*. A new tool added tomorrow
  inherits the workspace default, which is fail-open-by-timeout."
- "The classifier is a heuristic bootstrap. The product is the coverage
  metric and the review workflow, not classifier accuracy."
- "You already built the inventory — the MCP registry. This is the layer
  above it: what each tool does, what should happen when the check can't
  answer, and how much of the estate is still unknown."
- The one-liner: **"Unknown risk should fail closed until proven otherwise —
  and the coverage metric tells the CISO how much of the estate is unknown."**

## Honesty notes (say these before you're asked)

- `failOnError`, `deny`, and org/workspace/server-scoped guardrails already
  exist; Act 2 shows them working. The gap is the missing risk-derived,
  verification-gated policy layer — not the primitive.
- **Tool descriptions are attacker-controlled.** The classifier treats them
  as able to *lower* trust, never raise it — and because only VERIFIED
  labels earn fail-open, a poisoned description fails closed by default.
- **The demo runs on the LLM chat path with a structured `tool_call` field,
  not native MCP `tools/call`.** It's a mechanism demo; the natural home is
  the MCP gateway, which reads the tool name from the protocol itself.
- **The tier-2 audit receipt is fired by the enforcement point, not the
  gateway.** We found the OSS gateway's `async: true` hook accepts the
  request and returns instantly but never actually delivers the webhook call
  in this build — worth knowing in its own right. The proxy fires the audit
  after answering, so the receipt exists and the request never waited.
