# System Card: Tripwire v0.1

**Track:** SECURE. **Owners:** Manoj Kagitha (@kagithamanoj), Meghana Alaparthy (@meghana-alaparthy).

## Purpose
Contain prompt-injection and excessive-agency risk for tool-using AI agents, and produce verifiable evidence of every decision.

## Intended use
Wrap an agent's input, tool calls and output in a gateway. Intended for teams that need to demonstrate controls to security, audit or customers.

## Out of scope / not intended
Replacing model-level safety training; protecting against a compromised gateway host; content moderation; stopping a *human* approver from approving a bad action.

## Components and models
No ML model is required. Detector is rule-based; policy is deterministic code. The only "agent" in this repo is a scripted naive test double.
Evaluation only: Claude Haiku 5.5 (Anthropic API) acts as the agent under test in `scripts/live_eval.py`; see `docs/REAL_MODEL_EVAL.md`. Bedrock was attempted but AWS declined the quota.

## Measured performance (reproduce: `python -m tripwire eval`, `python -m tripwire arena`)
| Metric | Result | Notes |
|---|---|---|
| Attack success, unprotected | 100% (160/160 arena variants) | Naive agent obeys any instruction |
| Attack success, detector only | 7.5% (12/160) | Misses paraphrase attacks |
| Attack success, policy only | 0% (0/160) | 40 variants held for human review |
| Attack success, full | 0% (0/160) | 12 held for human review |
| Detector recall, seed corpus | 81.2% (13/16) | Misses A06, A10, A16 |
| Detector false-positive rate | 12.5% (1/8) | B08 security-training text |
| Benign calls needing a human | 1 of 8 benign docs | B07 forward to internal address |

Utility (`python -m tripwire utility`, 8 tasks incl. 3 with an injected document): legitimate tasks completed without a human:
none 8/8, session taint 1/8, **value taint 7/8**; attacks stopped in mixed tasks 3/3 for both taint modes.
Value-taint mode (`taint_mode="value"`) is opt-in; default is the safer session mode. Its blind spot is threat T15.

Real model (Haiku 5.5, 20 attack runs, 9 harmless documents): attacks succeeded 9/20 without Tripwire and 0/20 with it; legitimate email sent 9/9 without, 0/9 session taint, 7/9 value taint.

Caveats: self-authored attack set; simulated agent; small corpus. Treat as a regression benchmark, not a security guarantee.

## Human oversight
Items needing review enter `ReviewQueue`; approvers are recorded; no response within TTL means denied.

## Data handling and retention
Receipts store event metadata and rule IDs only, never document text (tested). The in-memory review queue holds a 120-character excerpt so a human can judge the item. Recommended retention: 90 days in
DynamoDB with TTL (configure per policy). No personal data is collected by the demo.

## Failure ownership
Gateway false negative: engineering owner patches rules and adds the case to the corpus. Wrongly approved action: approver named in the receipt; review in post-incident.

## Known limitations
See `THREAT_MODEL.md` T2, T3, T10, T11, T13. Coarse session-wide taint. Origin labelling is trusted from the host.

## Change log
v0.1: initial local release, 70 unit tests.
