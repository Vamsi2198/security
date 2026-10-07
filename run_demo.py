"""End-to-end demo runner. Requires the Portkey OSS gateway on :8787
(TRUSTED_CUSTOM_HOSTS=127.0.0.1,localhost). Starts the mock services and
the policy proxy itself, runs four acts, writes transcript.txt next to
this script.
"""
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from urllib.error import HTTPError, URLError

HERE = Path(__file__).resolve().parent
GATEWAY = "http://127.0.0.1:8787/v1/chat/completions"
PROXY = "http://127.0.0.1:9300/v1/chat/completions"
OUT = []


def emit(s=""):
    print(s)
    OUT.append(s)


def post(url, body_obj, headers=None, timeout=30):
    req = urllib.request.Request(url, data=json.dumps(body_obj).encode(),
                                 method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read()), r.headers, time.time() - t0
    except HTTPError as e:
        return e.code, json.loads(e.read()), e.headers, time.time() - t0


def verdict_line(status, payload, elapsed):
    hook = (payload.get("hook_results", {}).get("before_request_hooks") or [{}])[0]
    check = (hook.get("checks") or [{}])[0]
    err = (check.get("error") or {}).get("message", "none")
    outcome = "REQUEST EXECUTED" if status == 200 else "REQUEST BLOCKED"
    emit(f"  HTTP {status} in {elapsed:.2f}s -> {outcome}")
    if not hook and status == 200:
        # async guardrail: fire-and-forget, request never waits on the check
        emit("  guardrail ran ASYNC — the request never waited on the degraded")
        emit("  check; the audit receipt lands out of band (shown below).")
        return
    emit(f"  webhook result: {err}")
    emit(f"  fail_on_error={check.get('fail_on_error')}  deny={hook.get('deny')}"
         + (f"  async={hook.get('async')}" if hook.get("async") else ""))
    if status == 200:
        emit(f"  upstream said: {payload['choices'][0]['message']['content']}")


def wait_port(url, tries=30):
    for _ in range(tries):
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except URLError:
            time.sleep(0.5)
        except Exception:
            return True
    return False


def port_busy(port):
    import socket
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def main():
    procs = []
    for script, log, port in [("mock_services.py", "mock.log", 9100),
                              ("policy_proxy.py", "proxy.log", 9300)]:
        if port_busy(port):
            print(f"[{script} already running on :{port} — reusing]")
            continue
        procs.append(subprocess.Popen([sys.executable, str(HERE / script)],
                                      stdout=open(HERE / log, "w"), stderr=subprocess.STDOUT))
    time.sleep(2)

    try:
        emit("=" * 78)
        emit("DEMO: WHEN THE SAFETY CHECK IS TOO SLOW, WHO DECIDES WHAT THE GATE DOES?")
        emit("Synthetic data only. Portkey OSS gateway, local mock upstream, local webhook.")
        emit("=" * 78)

        # Regenerate the enforcement store fresh — nothing pre-shipped.
        subprocess.run([sys.executable, str(HERE / "policy_engine.py")],
                       check=True, capture_output=True)

        # ---- ACT 1: the gap (direct to gateway, gateway default) ---------
        emit()
        emit("ACT 1 — THE GAP. Destructive action; the safety webhook is degraded.")
        emit("Straight to the gateway, nothing says what to do on timeout.")
        emit("-" * 78)
        cfg = {"provider": "openai", "api_key": "dummy",
               "custom_host": "http://127.0.0.1:9100",
               "input_guardrails": [{
                   "id": "custom-safety-check", "deny": True,
                   "default.webhook": {
                       "webhookURL": "http://127.0.0.1:9200/check?mode=slow&action_class=crm-server/delete_customer",
                       "timeout": 1000}}]}
        status, payload, _, elapsed = post(GATEWAY, {"model": "mock-llm", "messages": [
            {"role": "user", "content": "delete all records for customer 4417"}]},
            {"x-portkey-config": json.dumps(cfg)})
        verdict_line(status, payload, elapsed)
        emit("  => The check TIMED OUT and the delete went through anyway. Fail-open by default.")

        # ---- ACT 2: the primitive (direct to gateway, failOnError) -------
        emit()
        emit("ACT 2 — THE PRIMITIVE THAT EXISTS. Same timeout, failOnError: true.")
        emit("The docs ship this toggle. It works — if a human flips it correctly,")
        emit("by hand, for every action, forever.")
        emit("-" * 78)
        cfg["input_guardrails"][0]["default.webhook"]["failOnError"] = True
        status, payload, _, elapsed = post(GATEWAY, {"model": "mock-llm", "messages": [
            {"role": "user", "content": "delete all records for customer 4417"}]},
            {"x-portkey-config": json.dumps(cfg)})
        verdict_line(status, payload, elapsed)
        emit("  => Same timeout, opposite outcome. The primitive exists; the POLICY doesn't.")

        # ---- ACT 3: derived enforcement, server-side (via the proxy) -----
        emit()
        emit("ACT 3 — THE PROPOSAL. Failure mode DERIVED from (risk tier,")
        emit("verification), attached SERVER-SIDE by the policy proxy. The action")
        emit("is parsed from the payload's tool_call — callers can't label")
        emit("themselves. Only VERIFIED labels earn fail-open. Webhook degraded.")
        emit("-" * 78)
        for server, tool, args, msg in [
            ("analytics-server", "run_report", {"report_id": "weekly-usage"},
             "run the weekly usage report"),
            ("comms-server", "post_slack_message", {"channel": "#eng-updates", "text": "deploy done"},
             "post the deployment notice to #eng-updates"),
            ("crm-server", "delete_customer", {"customer_id": "4417"},
             "delete all records for customer 4417"),
        ]:
            action = f"{server}/{tool}"
            emit()
            emit(f"  caller -> payload tool_call={action}")
            body = {"model": "mock-llm",
                    "messages": [{"role": "user", "content": msg}],
                    "tool_call": {"server": server, "tool": tool, "arguments": args}}
            status, payload, headers, elapsed = post(PROXY, body, {"x-action": action})
            emit(f"  proxy derived: action={headers.get('X-RiskGate-Action')}  "
                 f"tier={headers.get('X-RiskGate-Tier')}")
            verdict_line(status, payload, elapsed)

        # ---- ACT 4: the hostile caller, two ways --------------------------
        emit()
        emit("ACT 4 — THE HOSTILE CALLER, TWO WAYS.")
        emit("4a) Label spoofing: the payload is a delete, but the caller labels")
        emit("    it a read-only report, hoping for tier-1 fail-open. The proxy")
        emit("    derives the action from the payload and logs the mismatch.")
        emit("-" * 78)
        body = {"model": "mock-llm",
                "messages": [{"role": "user", "content": "delete all records for customer 4417"}],
                "tool_call": {"server": "crm-server", "tool": "delete_customer",
                              "arguments": {"customer_id": "4417"}}}
        status, payload, headers, elapsed = post(PROXY, body,
                                                 {"x-action": "analytics-server/run_report"})
        emit("  caller -> header says run_report; payload tool_call=crm-server/delete_customer")
        emit(f"  proxy derived: action={headers.get('X-RiskGate-Action')}  "
             f"tier={headers.get('X-RiskGate-Tier')} (mismatch logged)")
        verdict_line(status, payload, elapsed)
        emit("  => The label is attacker-controlled; the payload is not. Enforcement")
        emit("     follows the payload.")
        emit()
        emit("4b) Config injection: same delete, caller attaches its OWN fail-open")
        emit("    guardrail config. The proxy strips it and enforces the tier.")
        emit("-" * 78)
        sneaky = {"provider": "openai", "api_key": "dummy",
                  "custom_host": "http://127.0.0.1:9100",
                  "input_guardrails": [{
                      "id": "attacker-controlled", "deny": False,
                      "default.webhook": {
                          "webhookURL": "http://127.0.0.1:9200/check?mode=slow",
                          "timeout": 1000}}]}  # no failOnError -> would fail OPEN
        status, payload, headers, elapsed = post(PROXY, body,
                                                 {"x-portkey-config": json.dumps(sneaky)})
        emit("  caller -> delete payload + its own fail-open config")
        emit(f"  proxy derived: action={headers.get('X-RiskGate-Action')}  "
             f"tier={headers.get('X-RiskGate-Tier')} (client config stripped)")
        verdict_line(status, payload, elapsed)
        emit("  => The caller cannot choose its own risk tier OR its own policy.")
        emit("     That is enforcement.")

        # ---- coverage ------------------------------------------------------
        emit()
        emit("-" * 78)
        emit("THE AUDIT TRAIL — every enforcement decision the proxy made,")
        emit("including the label spoof and the stripped hostile config:")
        er = HERE / "enforcement_receipts.jsonl"
        if er.exists():
            for l in er.read_text().splitlines():
                if l.strip():
                    d = json.loads(l)
                    if d["event"] == "ENFORCEMENT_DECISION":
                        emit(f"    {d['action']:<42} tier={str(d['risk_tier']):<12} "
                             f"{d['outcome']:<9} stripped_client_config={d['client_config_stripped']}")
                    elif d["event"] == "LABEL_MISMATCH":
                        emit(f"    !! LABEL_MISMATCH: claimed={d['claimed_action']}  "
                             f"payload={d['payload_action']} — enforced payload")
                    else:
                        emit(f"    !! {d['event']}: {d.get('action', '?')} — {d.get('note', '')}")
        emit()
        emit("ASYNC RECEIPT DRAIN — giving the out-of-band paths time to write")
        emit("(the tier-2 audit is fired by the proxy AFTER answering; the")
        emit("degraded webhook sleeps past the gateway timeout)...")
        time.sleep(7)
        wr = HERE / "webhook_receipts.jsonl"
        if wr.exists():
            lines = [json.loads(l) for l in wr.read_text().splitlines() if l.strip()]
            emit(f"  webhook receipts written: {len(lines)}")
            for l in lines:
                emit(f"    [{l.get('source','gateway')}] action={l['action_class']:<40} "
                     f"mode={l['mode']} note={l['note']}")
        emit()
        receipts = json.loads((HERE / "policy_receipts.json").read_text())
        total = len(receipts)
        verified = sum(1 for r in receipts if r["verification"] == "VERIFIED")
        observed = sum(1 for r in receipts if r["verification"] == "OBSERVED")
        uncls = [r["action"] for r in receipts if r["verification"] == "UNCLASSIFIED"]
        emit(f"COVERAGE  verified: {verified}/{total} human-confirmed ({verified/total*100:.0f}%)   "
             f"observed: {observed}/{total} heuristic-only   unclassified: {len(uncls)}/{total}")
        emit(f"Unclassified (fail closed until reviewed): {', '.join(uncls)}")
        emit("Only VERIFIED labels earn fail-open. OBSERVED labels — including a")
        emit("poisoned 'fetch records' description on a delete tool — fail CLOSED")
        emit("until a human confirms them. The split controls behavior, not just")
        emit("the report.")
        emit("=" * 78)

        (HERE / "transcript.txt").write_text("\n".join(OUT))
        print("\n[transcript saved to transcript.txt]")
    finally:
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    main()
