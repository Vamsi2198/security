"""Risk-tier policy engine (synthetic data only).

The pitch in code:
  Portkey today maps guardrails to *scope* (org / workspace / server / tool)
  by hand. This layer maps enforcement to *risk* — derived from what a tool
  does — and reports how much of the estate anyone has actually confirmed.

  Tier 1  read-only            -> fail OPEN   (availability wins)
  Tier 2  internal write       -> fail OPEN + async receipt (observed, audited)
  Tier 3  destructive/external -> fail CLOSED (safety wins)
  UNCLASSIFIED                 -> fail CLOSED (unknown risk defaults shut)

Verification states (this is the denominator thesis applied to itself):
  OBSERVED  = heuristic label from tool metadata. Provisional.
  VERIFIED  = a human confirmed (or corrected) the tier. Trusted.
  The coverage metric reports both. Regex guesses are NOT counted as
  verified — a security reviewer would catch that in minutes.

Outputs are written next to this script (no hardcoded paths).
"""
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ---------------- Synthetic tool inventory (fake servers, fake tools) --------
INVENTORY = [
    ("crm-server", "get_customer", "Fetch a customer record by ID", ["customer_id"]),
    ("crm-server", "list_customers", "List customers with filters", ["filter"]),
    ("crm-server", "update_customer_email", "Change a customer's email address", ["customer_id", "email"]),
    ("crm-server", "delete_customer", "Permanently delete a customer record", ["customer_id"]),
    ("crm-server", "merge_accounts", "Merge two customer accounts irreversibly", ["src_id", "dst_id"]),
    ("comms-server", "send_email", "Send an email to an external address", ["to", "subject", "body"]),
    ("comms-server", "post_slack_message", "Post a message to an internal Slack channel", ["channel", "text"]),
    ("comms-server", "read_thread", "Read a conversation thread", ["thread_id"]),
    ("analytics-server", "run_report", "Run a read-only analytics report", ["report_id"]),
    ("analytics-server", "export_dataset", "Export a dataset to an external bucket", ["dataset_id", "bucket"]),
    ("analytics-server", "zql_query", "Run a ZQL query", ["query"]),
    ("billing-server", "get_invoice", "Fetch an invoice", ["invoice_id"]),
    ("billing-server", "refund_payment", "Issue a refund to a customer", ["payment_id", "amount"]),
    ("billing-server", "reconcile_ledger", "Reconcile ledger entries across periods", ["since"]),
]

# Marker order matters: destructive > external > write > read.
# Descriptions can only LOWER trust, never raise it (see human review note).
DESTRUCTIVE = re.compile(r"\b(delete|drop|purge|destroy|merge|erase|wipe|refund)\b", re.I)
EXTERNAL = re.compile(r"\b(send|export|external|bucket|sms)\b", re.I)
WRITE = re.compile(r"\b(update|change|write|create|modify|set|insert|post)\b", re.I)
READ = re.compile(r"\b(get|list|fetch|read|run.*report|query|view|search)\b", re.I)

TIER_LABEL = {1: "read-only", 2: "internal-write", 3: "destructive-or-external"}

# Human review queue: a security engineer confirms or CORRECTS heuristic tiers.
# This is the only path from OBSERVED to VERIFIED.
REVIEW_FILE = HERE / "human_review.json"


def classify(server, tool, description, params):
    text = f"{tool} {description}"
    if DESTRUCTIVE.search(text) or EXTERNAL.search(text):
        return 3, "matched destructive/external marker"
    if WRITE.search(text):
        return 2, "matched write marker"
    if READ.search(text):
        return 1, "matched read marker"
    return None, "no marker matched — needs human review"


def failure_mode(tier, status):
    """Availability privileges require VERIFIED. A heuristic guess (OBSERVED)
    never earns fail-open, and neither does an unknown action. This is what
    makes the verified/observed split control behavior, not just the report:
    a delete tool DESCRIBED as 'fetch records' gets an observed tier 1 —
    and still fails closed until a human confirms it."""
    if status != "VERIFIED":
        return "fail_closed"
    return {1: "fail_open", 2: "fail_open_with_async_receipt", 3: "fail_closed"}[tier]


def derive_config(tool_full_name, tier, status):
    """Generate the Portkey gateway guardrail config for one action.
    failOnError is DERIVED from (tier, verification), never hand-flipped.
    Verified tier 2 adds async: true so the audit path never blocks the
    request; the enforcement point fires the audit receipt out of band."""
    fm = failure_mode(tier, status)
    return {
        "action": tool_full_name,
        "risk_tier": tier if tier else "UNCLASSIFIED",
        "verification": status,
        "input_guardrails": [{
            "id": f"risk-gate::{tool_full_name}",
            "deny": True,
            **({"async": True} if fm == "fail_open_with_async_receipt" else {}),
            "default.webhook": {
                "webhookURL": f"http://127.0.0.1:9200/check?action_class={tool_full_name}",
                "timeout": 1000,
                "failOnError": fm == "fail_closed",
            },
        }],
    }


def load_human_review():
    if REVIEW_FILE.exists():
        return json.loads(REVIEW_FILE.read_text())
    return {}


def main():
    review = load_human_review()  # {action: {"tier": n, "reviewer": str, "note": str}}
    receipts, configs = [], {}
    counts = {"VERIFIED": 0, "OBSERVED": 0, "UNCLASSIFIED": 0}

    for server, tool, desc, params in INVENTORY:
        full = f"{server}/{tool}"
        tier, reason = classify(server, tool, desc, params)
        status = "OBSERVED" if tier else "UNCLASSIFIED"

        if full in review:
            r = review[full]
            changed = " (human CORRECTED heuristic)" if r["tier"] != tier else ""
            tier, status = r["tier"], "VERIFIED"
            reason = f"human review by {r['reviewer']}: {r['note']}{changed}"

        counts[status] += 1
        cfg = derive_config(full, tier, status)
        configs[full] = cfg
        receipts.append({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": full,
            "risk_tier": tier if tier else "UNCLASSIFIED",
            "tier_label": TIER_LABEL.get(tier, "unknown"),
            "verification": status,
            "classifier_reason": reason,
            "derived_failure_mode": failure_mode(tier, status),
        })

    total = len(INVENTORY)
    print("=" * 84)
    print("RISK-TIER POLICY ENGINE — classification, verification, derived enforcement")
    print("=" * 84)
    for r in receipts:
        tier = str(r["risk_tier"]).ljust(12)
        ver = r["verification"].ljust(12)
        print(f"  {r['action']:<42} tier={tier} {ver} -> {r['derived_failure_mode']}")
    print("-" * 84)
    print(f"COVERAGE  verified: {counts['VERIFIED']}/{total} human-confirmed "
          f"({counts['VERIFIED']/total*100:.0f}%)   "
          f"observed: {counts['OBSERVED']}/{total} heuristic-only   "
          f"unclassified: {counts['UNCLASSIFIED']}/{total}")
    print("The number a CISO trusts is the VERIFIED share. Only VERIFIED labels")
    print("earn availability privileges; OBSERVED and UNCLASSIFIED actions fail")
    print("CLOSED until a human confirms them. A poisoned description can lower")
    print("trust, never raise it.")
    print("=" * 84)

    (HERE / "policy_receipts.json").write_text(json.dumps(receipts, indent=2))
    (HERE / "derived_configs.json").write_text(json.dumps(configs, indent=2))
    print("wrote policy_receipts.json and derived_configs.json (next to this script)")

    if "--verify" in sys.argv:
        print("\nhuman_review.json present — rerun to apply.")


if __name__ == "__main__":
    main()
