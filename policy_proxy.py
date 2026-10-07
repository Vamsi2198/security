"""Server-side policy proxy — the enforcement point.

Sits between callers and the Portkey gateway. This is what makes the demo
real enforcement instead of a convention:

  - The caller sends a request whose BODY carries a structured tool_call
    (server + tool). The proxy derives the action from the payload itself.
    Caller-supplied labels (headers) are at most hints; a mismatch between
    the claimed label and the payload is logged as a security signal.
  - Any client-supplied `x-portkey-config` is STRIPPED and logged as a
    hostile/noisy signal.
  - The proxy looks up the action in the server-side enforcement store
    (derived_configs.json, produced by policy_engine.py) and attaches the
    derived guardrail ITSELF.
  - Unknown action -> default fail-CLOSED guardrail. Unknown risk fails shut.

In the product this role is played by server-side attachment (org/workspace
guardrails, or the MCP guardrail API mapping rules to servers/tools). The
OSS gateway alone doesn't persist per-action policies, so the demo uses this
thin shim to show the same property: the caller cannot choose its own tier.
"""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import request as urlreq
from urllib.error import HTTPError

HERE = Path(__file__).resolve().parent
GATEWAY = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8787/v1/chat/completions")
RECEIPTS = HERE / "enforcement_receipts.jsonl"

# Deployment configuration (all optional; laptop defaults preserve demo behavior)
PORT = int(os.environ.get("PORT", "9300"))
BIND = os.environ.get("BIND", "127.0.0.1")
DEMO_TOKEN = os.environ.get("DEMO_TOKEN", "")

BASE_TARGET = {"provider": "openai", "api_key": "dummy",
               "custom_host": "http://127.0.0.1:9100"}

_lock = threading.Lock()


def log_receipt(entry):
    entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with _lock, open(RECEIPTS, "a") as f:
        f.write(json.dumps(entry) + "\n")


def load_store():
    return json.loads((HERE / "derived_configs.json").read_text())


def guardrail_for(action, store):
    """Derived guardrail for a known action; fail-closed default for unknown."""
    if action in store:
        g = json.loads(json.dumps(store[action]["input_guardrails"]))
        tier = store[action]["risk_tier"]
    else:
        g = [{
            "id": f"risk-gate::UNKNOWN::{action}",
            "deny": True,
            "default.webhook": {
                "webhookURL": f"http://127.0.0.1:9200/check?action_class=UNCLASSIFIED:{action}",
                "timeout": 1000,
                "failOnError": True,
            },
        }]
        tier = "UNCLASSIFIED"
    # Demo scenario: the safety webhook is DEGRADED. In production the
    # webhook URL would not carry this parameter.
    for hook in g:
        hook["default.webhook"]["webhookURL"] += "&mode=slow"
    return g, tier


def action_from_payload(body):
    """Derive the action from the request PAYLOAD, never from caller claims.
    The request carries a structured tool_call; the proxy parses it itself.
    In the product this is the MCP gateway reading the tools/call name."""
    try:
        tc = json.loads(body).get("tool_call") or {}
        server, tool = tc.get("server"), tc.get("tool")
        if server and tool:
            return f"{server}/{tool}"
    except (json.JSONDecodeError, AttributeError):
        pass
    return None


def fire_audit_receipt(action):
    """Tier-2 audit, fired out of band. The request path never waits on it.
    (In this demo the safety webhook is degraded; the receipt still lands,
    because the enforcement point — not the request — owns the audit.)"""
    def _send():
        try:
            url = (f"http://127.0.0.1:9200/check?mode=slow&source=proxy-audit"
                   f"&action_class={action}")
            urlreq.urlopen(urlreq.Request(url, data=b"{}", method="POST",
                                          headers={"Content-Type": "application/json"}),
                           timeout=15)
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()


class ProxyHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, obj, extra_headers=None):
        payload = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        # Render health checks need a GET endpoint that answers without auth.
        if self.path.rstrip("/") in ("", "/healthz"):
            self._send_json(200, {"status": "ok", "service": "risk-gate-demo"})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        # Demo-token auth. On brand: a missing or wrong token fails CLOSED.
        if DEMO_TOKEN and self.headers.get("x-demo-token") != DEMO_TOKEN:
            log_receipt({"component": "policy_proxy", "event": "AUTH_REJECTED",
                         "note": "missing or wrong x-demo-token"})
            self._send_json(401, {"error": {"message": "missing or wrong x-demo-token",
                                            "type": "auth_failed"}})
            return

        store = load_store()
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        # Action comes from the payload. The x-action header is at most a
        # hint; a mismatch between claim and payload is a security signal.
        claimed = self.headers.get("x-action")
        action = action_from_payload(body)
        if claimed and action and claimed != action:
            log_receipt({"component": "policy_proxy", "event": "LABEL_MISMATCH",
                         "claimed_action": claimed, "payload_action": action,
                         "note": "caller-labeled action disagrees with payload — enforcing payload"})
        if not action:
            action = "UNSTRUCTURED:no-tool-call"

        stripped = False
        if self.headers.get("x-portkey-config"):
            stripped = True
            log_receipt({"component": "policy_proxy", "event": "STRIPPED_CLIENT_CONFIG",
                         "action": action,
                         "note": "caller tried to attach its own guardrail config — removed"})

        guardrails, tier = guardrail_for(action, store)
        config = {**BASE_TARGET, "input_guardrails": guardrails}

        req = urlreq.Request(GATEWAY, data=body, method="POST", headers={
            "Content-Type": "application/json",
            "x-portkey-config": json.dumps(config),
        })
        try:
            with urlreq.urlopen(req) as r:
                status, payload = r.status, r.read()
        except HTTPError as e:
            status, payload = e.code, e.read()
        except Exception as e:  # gateway unreachable etc. — fail CLOSED
            status = 502
            payload = json.dumps({"error": {"message": f"policy proxy upstream failure (failing closed): {e}",
                                            "type": "proxy_upstream_error"}}).encode()

        outcome = "EXECUTED" if status == 200 else "BLOCKED"
        log_receipt({"component": "policy_proxy", "event": "ENFORCEMENT_DECISION",
                     "action": action, "risk_tier": tier,
                     "outcome": outcome, "http_status": status,
                     "client_config_stripped": stripped})

        if status == 200 and str(tier) == "2":
            fire_audit_receipt(action)  # out of band; request already answered

        self._send_json(status, json.loads(payload), {
            "X-RiskGate-Action": action,
            "X-RiskGate-Tier": str(tier),
            "X-RiskGate-Outcome": outcome,
        })

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    # PORT: Render injects it (default 10000); 9300 locally.
    # BIND: 0.0.0.0 in the container; override with BIND=127.0.0.1 for laptop runs.
    port = PORT
    print(f"policy-proxy -> http://{BIND}:{port}  (action parsed from payload tool_call)")
    print("client config stripped; labels treated as hints; unknown actions fail closed")
    if DEMO_TOKEN:
        print("demo-token auth: ON (x-demo-token required)")
    else:
        print("demo-token auth: OFF (set DEMO_TOKEN to require it)")
    ThreadingHTTPServer((BIND, port), ProxyHandler).serve_forever()
