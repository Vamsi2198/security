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


# Demo console: one static page served at GET / so visitors can try the
# enforcement point from a browser. No auth needed to READ the page; the
# token is only sent on the POSTs, same as curl.
DEMO_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Risk-Gate Demo Console</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 980px; margin: 2rem auto; padding: 0 1rem; color: #222; }
  h1 { font-size: 1.4rem; } h2 { font-size: 1.05rem; margin-top: 1.6rem; }
  .sub { color: #666; }
  code { background: #eee; padding: 0 .3em; border-radius: 4px; }
  button { font-size: .95rem; padding: .55rem 1rem; border: 0; border-radius: 6px; background: #146eb4; color: #fff; cursor: pointer; margin: .2rem .2rem .2rem 0; }
  button:hover { background: #0f5590; }
  button small { display: block; font-weight: normal; opacity: .85; }
  #token { width: 100%; max-width: 340px; padding: .5rem; border: 1px solid #bbb; border-radius: 6px; }
  pre { background: #111; color: #0d0; padding: 1rem; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; min-height: 120px; }
  .pass { color: #0a0; font-weight: 600; } .block { color: #c00; font-weight: 600; }
  table { border-collapse: collapse; margin-top: .5rem; } td, th { border: 1px solid #ccc; padding: .35rem .7rem; text-align: left; font-size: .9rem; }
</style>
</head>
<body>
<h1>Risk-Gate Demo Console</h1>
<p class="sub">When the safety check is too slow (or down), who decides what the gate
does? This proxy decides from the action's <b>risk tier</b> and whether a human
<b>verified</b> it &mdash; not from caller-supplied labels. Try the scenarios below.</p>

<h2>1. Enter your demo token</h2>
<input id="token" type="password" placeholder="DEMO_TOKEN (ask the demo host)">
<span class="sub">stored only in your browser's localStorage</span>

<h2>2. Fire a scenario</h2>
<div id="scenarios"></div>

<h2>3. Result</h2>
<div id="result"><pre>Pick a scenario above.</pre></div>

<h2>What to expect</h2>
<table>
<tr><th>Scenario</th><th>Derived tier</th><th>Expected</th><th>Why</th></tr>
<tr><td>Run usage report</td><td>1, VERIFIED</td><td class="pass">200 pass</td><td>Read-only + human-verified earns fail-open</td></tr>
<tr><td>Post to #eng-updates</td><td>2, VERIFIED</td><td class="pass">200 pass</td><td>Internal write passes + audit receipt fired</td></tr>
<tr><td>Delete customer</td><td>3, VERIFIED</td><td class="block">446 block</td><td>Destructive always fails closed</td></tr>
<tr><td>Spoofed label</td><td>3 (from payload)</td><td class="block">446 block</td><td>Header claims "report", payload is a delete &rarr; payload wins, mismatch logged</td></tr>
<tr><td>Unclassified tool</td><td>unknown</td><td class="block">446 block</td><td>Unknown risk fails closed until a human verifies it</td></tr>
</table>
<p class="sub">The safety webhook in this demo is deliberately degraded (slower than the
gateway timeout), so every decision you see is the failure-mode policy doing its job.</p>

<script>
const SCENARIOS = [
  {name: "Run usage report", hint: "expect 200",
   body: {model: "mock-llm", messages: [{role: "user", content: "run the weekly usage report"}],
          tool_call: {server: "analytics-server", tool: "run_report", arguments: {report_id: "weekly-usage"}}}},
  {name: "Post to #eng-updates", hint: "expect 200 + audit",
   body: {model: "mock-llm", messages: [{role: "user", content: "announce the deploy"}],
          tool_call: {server: "comms-server", tool: "post_slack_message", arguments: {channel: "#eng-updates", text: "deploy done"}}}},
  {name: "Delete customer 4417", hint: "expect 446",
   body: {model: "mock-llm", messages: [{role: "user", content: "delete all records for customer 4417"}],
          tool_call: {server: "crm-server", tool: "delete_customer", arguments: {customer_id: "4417"}}}},
  {name: "Spoofed label: claims 'report', is a delete", hint: "expect 446",
   spoof: "analytics-server/run_report",
   body: {model: "mock-llm", messages: [{role: "user", content: "delete all records for customer 4417"}],
          tool_call: {server: "crm-server", tool: "delete_customer", arguments: {customer_id: "4417"}}}},
  {name: "Unclassified tool (reconcile ledger)", hint: "expect 446",
   body: {model: "mock-llm", messages: [{role: "user", content: "reconcile the ledger"}],
          tool_call: {server: "billing-server", tool: "reconcile_ledger", arguments: {since: "2024-01"}}}},
];
const tok = document.getElementById('token');
tok.value = localStorage.getItem('riskgate_token') || '';
tok.addEventListener('change', () => localStorage.setItem('riskgate_token', tok.value));
const box = document.getElementById('scenarios');
for (const s of SCENARIOS) {
  const b = document.createElement('button');
  b.innerHTML = s.name + ' <small>' + s.hint + '</small>';
  b.onclick = () => fire(s);
  box.appendChild(b);
}
async function fire(s) {
  const out = document.getElementById('result');
  out.innerHTML = '<pre>sending ' + s.name + ' ... (first request after idle can take ~50s on the free tier)</pre>';
  const headers = {'Content-Type': 'application/json', 'x-demo-token': tok.value};
  if (s.spoof) headers['x-action'] = s.spoof;   // caller-supplied label: only a hint
  let lines = ['scenario : ' + s.name];
  try {
    const r = await fetch('/v1/chat/completions', {method: 'POST', headers, body: JSON.stringify(s.body)});
    const body = await r.text();
    lines.push('HTTP     : ' + r.status + ' ' + (r.status === 200 ? 'EXECUTED' : 'BLOCKED'));
    for (const h of ['X-RiskGate-Action', 'X-RiskGate-Tier', 'X-RiskGate-Outcome'])
      lines.push(h.replace('X-RiskGate-', 'gate      : ') + ' = ' + (r.headers.get(h) || '-'));
    lines.push('', 'response body:', body);
  } catch (e) {
    lines.push('request failed: ' + e);
  }
  out.innerHTML = '<pre></pre>';
  out.firstChild.textContent = lines.join('\\n');
}
</script>
</body>
</html>"""


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
        if self.path.rstrip("/") == "/healthz":
            self._send_json(200, {"status": "ok", "service": "risk-gate-demo"})
        elif self.path.rstrip("/") in ("", "/demo"):
            payload = DEMO_PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
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
