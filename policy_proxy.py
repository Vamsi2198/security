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
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import request as urlreq
from urllib.error import HTTPError

HERE = Path(__file__).resolve().parent
GATEWAY = "http://127.0.0.1:8787/v1/chat/completions"
RECEIPTS = HERE / "enforcement_receipts.jsonl"

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
    def do_POST(self):
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

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-RiskGate-Action", action)
        self.send_header("X-RiskGate-Tier", str(tier))
        self.send_header("X-RiskGate-Outcome", outcome)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("policy-proxy -> http://127.0.0.1:9300  (callers POST here with x-action header)")
    print("client-supplied x-portkey-config is always stripped; enforcement is server-side")
    ThreadingHTTPServer(("127.0.0.1", 9300), ProxyHandler).serve_forever()
