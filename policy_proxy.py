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


# Demo console: a guided flow served at GET / (and /demo). The server injects
# DEMO_TOKEN into the page, so visitors just press buttons — no token entry.
# Five numbered scenarios walk the policy (verified read → pass, verified
# write → pass + audit, destructive → block, spoofed label → block,
# unclassified → block), each with its expected outcome and a plain-English
# "what happened". A live audit trail streams from GET /receipts, and
# POST /reset clears the receipt logs for a clean re-run.
DEMO_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Risk-Gate Demo</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 1080px; margin: 2rem auto; padding: 0 1rem; color: #222; }
  h1 { font-size: 1.4rem; margin-bottom: .2rem; }
  h2 { font-size: 1.05rem; margin-top: 1.4rem; }
  .sub { color: #666; }
  code { background: #eee; padding: 0 .3em; border-radius: 4px; }
  button { font-size: .95rem; padding: .55rem 1rem; border: 0; border-radius: 6px; background: #146eb4; color: #fff; cursor: pointer; margin: .2rem .2rem .2rem 0; }
  button:hover { background: #0f5590; }
  button:disabled { background: #999; cursor: default; }
  button.ghost { background: #fff; color: #146eb4; border: 1px solid #146eb4; }
  .cols { display: grid; grid-template-columns: 1fr 330px; gap: 1.5rem; margin-top: 1rem; }
  @media (max-width: 900px) { .cols { grid-template-columns: 1fr; } }
  .card { border: 1px solid #ddd; border-radius: 10px; padding: .9rem 1rem; margin-bottom: .8rem; }
  .card h3 { font-size: 1rem; margin: 0 0 .15rem; }
  .hint { font-size: .85rem; color: #666; }
  .chip { display: inline-block; font-size: .78rem; font-weight: 700; padding: .12rem .6rem; border-radius: 999px; margin-left: .4rem; }
  .chip.ok { background: #e6f6ec; color: #0a7d33; }
  .chip.bad { background: #fdeceb; color: #c0392b; }
  .chip.wait { background: #f1f1f1; color: #666; }
  .result { display: none; margin-top: .6rem; font-size: .9rem; background: #f7f7f7; border-radius: 8px; padding: .6rem .8rem; }
  .result.show { display: block; }
  .result .why { margin: .45rem 0 0; }
  .result pre { margin: .3rem 0 0; white-space: pre-wrap; color: #444; }
  .pass { color: #0a7d33; font-weight: 700; }
  .block { color: #c0392b; font-weight: 700; }
  #audit { background: #111; color: #8f8; padding: .8rem; border-radius: 8px; font-family: ui-monospace, Consolas, monospace; font-size: .8rem; min-height: 180px; max-height: 440px; overflow-y: auto; white-space: pre-wrap; }
  #audit .empty { color: #777; }
  table { border-collapse: collapse; margin-top: .5rem; font-size: .88rem; }
  td, th { border: 1px solid #ccc; padding: .35rem .6rem; text-align: left; }
</style>
</head>
<body>
<h1>Risk-Gate Demo</h1>
<p class="sub">When the safety check is too slow to answer, who decides what the gate does?
This gate derives the answer from <b>what the action does</b> and whether a human
<b>verified it</b> &mdash; never from the caller's word. The safety webhook here is
deliberately degraded, so every result below is the failure-mode policy doing its job.
The demo token is built into this page: just work through the five scenarios.</p>

<p><button id="runall" onclick="runAll()">Run the whole story</button>
<span class="sub">fires all five in order, about 15 seconds. First request after an
idle stretch can be slow on a free-tier host &mdash; the services are waking up.</span></p>

<div class="cols">
  <div id="scenarios"></div>
  <div>
    <h2>Live audit trail</h2>
    <p class="sub">every decision the enforcement point makes streams here as it happens</p>
    <div id="audit"><span class="empty">(no events yet &mdash; fire a scenario)</span></div>
    <p><button class="ghost" onclick="resetAudit()">Reset audit trail</button></p>

    <h2>The policy in one table</h2>
    <table>
      <tr><th>Action class</th><th>During the outage</th></tr>
      <tr><td>VERIFIED tier 1 &mdash; read-only</td><td class="pass">pass</td></tr>
      <tr><td>VERIFIED tier 2 &mdash; internal write</td><td class="pass">pass + audit receipt</td></tr>
      <tr><td>VERIFIED tier 3 &mdash; destructive / external</td><td class="block">block</td></tr>
      <tr><td>OBSERVED &mdash; heuristic label only</td><td class="block">block until a human confirms</td></tr>
      <tr><td>UNCLASSIFIED &mdash; unknown</td><td class="block">block until reviewed</td></tr>
    </table>
    <p class="sub">Only human-verified labels earn availability. Every guess fails closed.</p>
  </div>
</div>

<p class="sub">Prefer <code>curl</code>? The same endpoints work directly:
<code>POST /v1/chat/completions</code> with header <code>x-demo-token</code>
(this page already carries it) and a <code>tool_call</code> in the body.</p>

<script>
const DEMO_TOKEN = __DEMO_TOKEN_JSON__;
const HEADERS = {'Content-Type': 'application/json'};
if (DEMO_TOKEN) HEADERS['x-demo-token'] = DEMO_TOKEN;

const SCENARIOS = [
  {name: 'A read-only report, human-verified',
   hint: 'VERIFIED tier 1 · expect PASS (200)',
   expect: 200,
   why: 'A human confirmed this tool only reads. Availability wins — it rides out the degraded check.',
   body: {model: 'mock-llm', messages: [{role: 'user', content: 'run the weekly usage report'}],
          tool_call: {server: 'analytics-server', tool: 'run_report', arguments: {report_id: 'weekly-usage'}}}},
  {name: 'An internal Slack post, human-verified',
   hint: 'VERIFIED tier 2 · expect PASS (200) + audit receipt',
   expect: 200,
   why: 'Passes in milliseconds — the check runs async — and the audit receipt lands out of band. Watch for it in the trail.',
   body: {model: 'mock-llm', messages: [{role: 'user', content: 'announce the deploy'}],
          tool_call: {server: 'comms-server', tool: 'post_slack_message', arguments: {channel: '#eng-updates', text: 'deploy done'}}}},
  {name: 'Delete a customer, human-verified destructive',
   hint: 'VERIFIED tier 3 · expect BLOCKED (446)',
   expect: 446,
   why: 'Destructive actions fail closed even when verified. Safety beats availability.',
   body: {model: 'mock-llm', messages: [{role: 'user', content: 'delete all records for customer 4417'}],
          tool_call: {server: 'crm-server', tool: 'delete_customer', arguments: {customer_id: '4417'}}}},
  {name: 'The liar: a delete labelled as a "report"',
   hint: 'spoofed label · expect BLOCKED (446)',
   expect: 446,
   why: 'The caller claims this is a read-only report. The proxy reads the actual tool_call from the payload, logs LABEL_MISMATCH, and enforces the payload. A label is a hint; the payload is the truth.',
   spoof: 'analytics-server/run_report',
   body: {model: 'mock-llm', messages: [{role: 'user', content: 'delete all records for customer 4417'}],
          tool_call: {server: 'crm-server', tool: 'delete_customer', arguments: {customer_id: '4417'}}}},
  {name: 'A tool nobody has classified yet',
   hint: 'UNCLASSIFIED · expect BLOCKED (446)',
   expect: 446,
   why: 'Unknown risk fails shut until a human reviews it. A tool added tomorrow never inherits the permissive default.',
   body: {model: 'mock-llm', messages: [{role: 'user', content: 'reconcile the ledger'}],
          tool_call: {server: 'billing-server', tool: 'reconcile_ledger', arguments: {since: '2024-01'}}}},
];

const box = document.getElementById('scenarios');
SCENARIOS.forEach((s, i) => {
  const card = document.createElement('div'); card.className = 'card';
  const h = document.createElement('h3');
  h.textContent = (i + 1) + '. ' + s.name;
  const chip = document.createElement('span'); chip.className = 'chip wait'; chip.textContent = 'not tried';
  h.appendChild(chip);
  const hint = document.createElement('div'); hint.className = 'hint'; hint.textContent = s.hint;
  const btn = document.createElement('button'); btn.textContent = 'Try it'; btn.style.marginTop = '.4rem';
  const result = document.createElement('div'); result.className = 'result';
  btn.onclick = () => fire(s);
  card.appendChild(h); card.appendChild(hint); card.appendChild(btn); card.appendChild(result);
  box.appendChild(card);
  s._btn = btn; s._chip = chip; s._result = result;
});

async function fire(s) {
  s._btn.disabled = true;
  s._chip.className = 'chip wait'; s._chip.textContent = 'sending…';
  s._result.className = 'result show';
  s._result.textContent = 'sending…';
  const t0 = Date.now();
  let lines, ok = false;
  try {
    const headers = Object.assign({}, HEADERS);
    if (s.spoof) headers['x-action'] = s.spoof;   // caller-supplied label: only a hint
    const r = await fetch('/v1/chat/completions', {method: 'POST', headers, body: JSON.stringify(s.body)});
    const elapsed = ((Date.now() - t0) / 1000).toFixed(2);
    const gate = ['X-RiskGate-Action', 'X-RiskGate-Tier', 'X-RiskGate-Outcome']
      .map(k => k.replace('X-RiskGate-', '').toLowerCase() + '=' + (r.headers.get(k) || '-'));
    ok = r.status === s.expect;
    lines = ['HTTP ' + r.status + ' in ' + elapsed + 's — ' + (r.status === 200 ? 'EXECUTED' : 'BLOCKED')
             + (ok ? '  (as expected)' : '  (UNEXPECTED — expected ' + s.expect + ')'),
             'gate:  ' + gate.join('  ')];
  } catch (e) {
    lines = ['request failed: ' + e];
  }
  const pre = document.createElement('pre'); pre.textContent = lines.join('\\n');
  const why = document.createElement('p'); why.className = 'why'; why.textContent = 'What happened: ' + s.why;
  s._result.textContent = '';
  s._result.appendChild(pre); s._result.appendChild(why);
  s._chip.className = 'chip ' + (ok ? 'ok' : 'bad');
  s._chip.textContent = ok ? (s.expect === 200 ? 'passed' : 'blocked') : 'check';
  s._btn.disabled = false;
  s._btn.textContent = 'Try again';
}

async function runAll() {
  const all = document.getElementById('runall');
  all.disabled = true;
  for (const s of SCENARIOS) {
    await fire(s);
    await new Promise(res => setTimeout(res, 1400));
  }
  all.disabled = false;
}

/* ---- live audit trail, fed by GET /receipts ---- */
let lastIdx = -1;
const auditEl = document.getElementById('audit');
function fmt(e) {
  const t = (e.ts || '').slice(11, 19);
  if (e.event === 'ENFORCEMENT_DECISION')
    return t + '  ' + (e.outcome === 'EXECUTED' ? 'ALLOW' : 'BLOCK') + '  ' + e.action
         + '  (tier ' + e.risk_tier + (e.client_config_stripped ? ', client config stripped' : '') + ')';
  if (e.event === 'LABEL_MISMATCH')
    return t + '  !! LABEL_MISMATCH — caller claimed ' + e.claimed_action + ' but the payload was '
         + e.payload_action + '; the payload was enforced';
  if (e.event === 'STRIPPED_CLIENT_CONFIG')
    return t + '  !! STRIPPED_CLIENT_CONFIG — caller-supplied guardrail config removed for ' + e.action;
  if (e.event === 'AUTH_REJECTED')
    return t + '  !! AUTH_REJECTED — missing or wrong x-demo-token; fails closed';
  return t + '  !! ' + e.event;
}
async function poll() {
  try {
    const r = await (await fetch('/receipts')).json();
    const evts = r.events || [];
    const fresh = evts.filter(e => e.i > lastIdx);
    if (!fresh.length) return;
    const empty = auditEl.querySelector('.empty');
    if (empty) empty.remove();
    fresh.forEach(e => {
      lastIdx = Math.max(lastIdx, e.i);
      const line = document.createElement('div');
      line.textContent = fmt(e);
      auditEl.appendChild(line);
    });
    auditEl.scrollTop = auditEl.scrollHeight;
  } catch (e) { /* trail pauses; the scenario buttons keep working */ }
}
setInterval(poll, 2000); poll();

async function resetAudit() {
  await fetch('/reset', {method: 'POST'});
  lastIdx = -1;
  auditEl.textContent = '';
  const span = document.createElement('span');
  span.className = 'empty';
  span.textContent = '(no events yet — fire a scenario)';
  auditEl.appendChild(span);
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
        elif self.path.rstrip("/") == "/receipts":
            # Feeds the demo console's live audit trail. Receipts are written
            # with json.dumps (ASCII-safe), so plain read_text is fine.
            events = []
            if RECEIPTS.exists():
                for i, line in enumerate(RECEIPTS.read_text().splitlines()):
                    if line.strip():
                        try:
                            d = json.loads(line)
                            d["i"] = i
                            events.append(d)
                        except json.JSONDecodeError:
                            continue
            self._send_json(200, {"events": events})
        elif self.path.rstrip("/") in ("", "/demo"):
            # The demo token is injected into the page so visitors don't type
            # it. This keeps casual abuse out; it is not secrecy — anyone can
            # read the token from the page source, same as any browser-sent
            # demo credential.
            page = DEMO_PAGE.replace("__DEMO_TOKEN_JSON__", json.dumps(DEMO_TOKEN or ""))
            payload = page.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        # Demo-console control: clear the receipt logs for a clean re-run.
        # Deliberately outside the token gate — it only truncates demo logs.
        if self.path.rstrip("/") == "/reset":
            files = [RECEIPTS, HERE / "webhook_receipts.jsonl"]
            for f in files:
                if f.exists():
                    f.write_text("")
            self._send_json(200, {"ok": True, "reset": [f.name for f in files]})
            return

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
