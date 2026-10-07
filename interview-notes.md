# Interview Notes — Prisma AIRS Principal PM

**Private prep doc. Not for sending.** Review the night before. The memo and
demo stay narrow; this doc holds the wider map for when the conversation
zooms out.

---

## 1. The one-sentence version

"The AI proposes. The tool executes. But an independent runtime authority
decides whether, under what conditions, and with what evidence the action is
allowed to happen — even when the safety infrastructure itself is failing."

## 2. Language to use in the room

- **UNKNOWN is a state.** Guardrail checks today collapse to pass/fail, and
  timeout silently becomes pass. Name the third state: UNKNOWN. Policy is
  what maps UNKNOWN × risk-tier → allow / async / deny.
- **PEP / PDP.** The gateway is the Policy Enforcement Point. What's missing
  is the Policy Decision Point above it — the layer that derives the decision
  from action identity, risk, verification state, and evidence requirements.
- **Claim vs. fact.** A caller's label for its own request is a claim; the
  payload's tool call is closer to an observable fact. "Never let the subject
  of an authorization decision define its own authorization attributes."
- **Two control loops.** Synchronous enforcement (can this happen?) and
  asynchronous evidence (what actually happened?). Enterprise buyers fund
  both; most products only demo the first.
- **Reversibility.** Why tier 3 can't be async: async verification can't
  undo a delete. Policy dimensions beyond risk: blast radius, reversibility,
  authority, confidence, freshness.

## 3. The four questions (locates the product gap precisely)

1. Is the request safe? → guardrails (exists)
2. Is the actor allowed to do it? → authorization (emerging)
3. What happens when we can't determine either? → **failure semantics /
   risk policy (the gap)**
4. Did the action produce the expected state? → post-action outcome
   verification (almost nobody has this; this is where AAGCP-Vector and the
   erasure-verification work finally becomes relevant — save it for here)

## 4. If asked "what else did you consider?"

The options catalog — showing you surveyed and rejected alternatives is a
Principal-level signal:

- **Always fail closed** — safe, terrible availability; a guardrail outage
  becomes an enterprise outage. Correct for money movement and destructive
  actions; wrong as a universal default.
- **Always fail open** — the status quo default; fine only where verification
  is informational.
- **Human approval** — right for critical irreversible actions ("AI wants to
  issue a $500K refund — ask someone"), but doesn't scale to every call.
- **Two-phase execution** — plan → simulate → preview → approve → commit.
  Strongest pattern for irreversible actions; heavier than a gateway hook.
- **Capability-based security** — agents hold explicit capability grants;
  stronger than classification alone, complementary to it.
- **Signed policy decisions** — PDP signs decisions the PEP must present.
  Real infrastructure, but watch the replay problem: signed ALLOWs become
  bearer tokens unless bound to request hashes with short TTLs. (Know this
  caveat before name-dropping it.)
- **Policy-as-code (OPA-style)** — the natural implementation form of the
  PDP: `action == "delete_customer" AND verification != VERIFIED → DENY`.
- **Circuit breaker** — stop paying the 1s timeout tax when the safety
  service is known-unhealthy; degrade posture by tier instead.
- **Queue-and-defer** — PENDING until the safety service recovers; good for
  latency-insensitive workflows.
- **Compensating transactions** — execute, verify, compensate on violation.
  Fine for reversible actions; never equivalent to prevention for deletes.

## 5. If asked "where does this go in three years?" (the vision answer)

Only now zoom out. The wedge is fail-open/fail-closed on timeout; the
destination is **Runtime Action Authority**: every consequential AI action
receives an independently derived authority decision before execution —
covering what action, who is asking, with what authority, what evidence, and
what happens under uncertainty or control-plane failure. Decisions include
ALLOW / MODIFY / HOLD / ESCALATE / BLOCK, each receipted into a decision
ledger. Fail-open/fail-closed is just one consequence of that model.

Sequence in the room: wedge first (they can verify it), denominator second
(they can't build it overnight), vision last (when they ask).

## 6. Your background as an asset, stated plainly

Data governance taught the denominator question — "what share of the estate
is actually classified, and who verified it?" — which is exactly the question
AI gateways can't answer today. That's the through-line from your governance
work to this role. AAGCP's observe → analyze → plan → simulate → execute →
learn loop maps onto this demo's runtime slice: observe the tool_call,
analyze risk/trust, plan the failure behavior, enforce, verify via receipts.

## 7. Pre-send checklist

- [ ] Run `python3 run_demo.py` on your own machine (gateway on :8787 with
      TRUSTED_CUSTOM_HOSTS). The memo says "I reproduced it" — make it true.
- [ ] Verify the async-hook quirk (async hook returns instantly, webhook
      never fires) on the current gateway build before mentioning it.
- [ ] Confirm tool-level MCP guardrail targeting status in current docs —
      say "server-level, tool-level emerging" unless you verified otherwise.
- [ ] Re-check the JetStream Clearance claim the week you send (fast-moving).
- [ ] One page stays one page. If a sentence can't survive a security
      reviewer reading the code, cut it.
