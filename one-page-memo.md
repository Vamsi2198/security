# When the safety check can't answer, who decides what the gate does?

**A product observation on Prisma AIRS / the Portkey gateway, with a working demo. Synthetic data only.**

---

## The observation (verifiable in five minutes)

When a custom guardrail webhook is too slow to answer, the gateway lets the
request through. The docs say so: on timeout, the default verdict is pass.
I reproduced it on the open-source gateway: a destructive request, a guardrail
check that times out at 1000ms — HTTP 200, request executed.

The precise way to say it: the gateway has no UNKNOWN state. A check has two
outcomes — pass or fail — and when the check can't answer at all, the timeout
is silently converted into a pass. UNKNOWN becomes ALLOW, by default, on every
action class alike.

This isn't a bug, and the fix isn't "add fail-closed." That primitive already
exists: `failOnError` on the check, `deny` on the guardrail, and org-,
workspace-, and server-scoped guardrails that enforce policy centrally. My
demo shows all of it working. The gap is somewhere else.

## The gap: enforcement is mapped to scope, not to risk

AI gateways today answer two questions: *is the request safe* (guardrails) and,
increasingly, *is the actor allowed* (authorization). The unanswered third
question is: **what should happen when we can't determine either?** Today the
answer is an accident of defaults. Every enforcement decision is attached
*by hand, by scope* — this org, this workspace, this server, this tool.
Nothing attaches enforcement to *what an action does*. Three consequences:

1. To fail closed on every destructive tool, an admin must know every
   destructive tool and attach the rule to each one.
2. A tool added tomorrow inherits the workspace default — which is
   fail-open-by-timeout. A fire-exit rule applied to a vault door.
3. Nobody can answer the coverage question: **what fraction of actions
   passing through this gateway has anyone classified at all?**

## The proposal: a risk-tiered policy layer

In classic terms: the gateway stays the Policy Enforcement Point; what's
missing is the Policy Decision Point above it. Concretely:

- **Derive the action from the payload, never from the caller.** In the
  product, the MCP gateway reads the `tools/call` name itself; a caller's
  label for its own request is a hint at most, and a mismatch is a security
  signal worth logging.
- **Classify actions by risk** from tool metadata — read-only, internal-write,
  destructive/external. Heuristics bootstrap; humans confirm. Descriptions
  are attacker-controlled, so they can only *lower* trust, never raise it.
- **Derive the failure mode from tier *and* verification.** Only a
  human-VERIFIED read-only tier fails open. Heuristic labels — including a
  delete tool described as "fetch records" — fail closed until confirmed.
  `failOnError` is never hand-flipped per tool again.
- **Unknown fails shut.** An unclassified tool gets fail-closed until
  reviewed. New tools no longer silently inherit the permissive default.
- **Report the denominator.** Coverage separates VERIFIED from OBSERVED. A
  regex guess is not governance. In my synthetic 14-tool estate: 5 verified,
  8 observed, 1 unclassified — and the observed 8 fail closed too. That
  split is the number a CISO can act on.

You already built the inventory — the MCP gateway registry knows every server
and tool. This is the layer above it.

## The evidence (10 minutes, runs anywhere)

On the OSS gateway, with a mock upstream and a deliberately degraded webhook:

| Act | Setup | Result |
|---|---|---|
| 1. The gap | Destructive request, check times out, gateway default | **200 — executed** |
| 2. The primitive | Same, with `failOnError: true` | **446 — blocked** |
| 3. The proposal | Failure mode derived from (tier, verification), attached server-side, action parsed from payload | verified read: 200 · verified internal write: 200 + async audit · delete: **446** |
| 4. The hostile caller | (a) labels a delete as a read-only report; (b) attaches its own fail-open config | spoof logged, **446** · config stripped, **446** |

Every decision is receipted: what ran, which tier and verification state
decided, and every attempt by the caller to choose its own label or policy.

## Why this matters for Prisma AIRS

The acquisition made the gateway the enforcement point for enterprise AI
security. The buyer is now the CISO, not only the developer — and the CISO's
question is never "did the check run?" but "what happens when it can't, and
how much of my estate is governed?" The market is already moving to the
action layer: JetStream Clearance (announced at Fal.Con 2026, backed by
Redpoint and the CrowdStrike Falcon Fund) sells pre-execution authorization
down to individual tool-call parameters. The team that turns enforcement
from hand-mapped scope into risk-derived, verification-gated policy — with a
coverage number on the dashboard — owns the CISO conversation.

## What this demo is not (I'd say this in the room)

- Tool descriptions are attacker-controlled; the classifier treats them as
  able to *lower* trust, never raise it, and unverified labels fail closed.
- It runs on the chat path with a structured `tool_call` field as a
  mechanism demo; the natural home is native MCP `tools/call`.
- It uses synthetic tools, a mock LLM, and a local webhook. Nothing from
  client work.

---

*I'd love to show you the demo — it runs in ten minutes on a laptop.*
