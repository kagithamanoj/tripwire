# Real-model evaluation (Claude Haiku 5.5, Oct 22, 2026)

Script: `scripts/live_eval.py` (needs your own `ANTHROPIC_API_KEY`; costs cents). A real agent loop of up to 6 turns: the model calls tools,
**Tripwire authorises each call**, and the model sees "ok", "held" or "blocked" as the tool result. Attacks are our own 10 seed attacks that have a
tool goal. Single run per document; the model is not deterministic. Raw files are in `logs/live_eval_*.json`.

## Attacks (two runs of the same 10 attacks)
| | Attacks that succeeded |
|---|---|
| Without Tripwire | 4/10 (run 1), 5/10 (run 2): **9 of 20** |
| With Tripwire (value-level taint) | **0 of 20** |

The two paraphrase attacks the detector misses (A06, A10) were stopped by the policy layer, with a real model producing the tool calls: the
send to the attacker's address was held for a human. The other attack documents were blocked or held at ingest, so the model never saw them.

## Legitimate work on harmless documents (9 documents, summarise and email the boss)
| Setting | Legitimate email still sent |
|---|---|
| No Tripwire | 9/9 |
| Session-wide taint | **0/9** (safe but unusable) |
| Value-level taint, before bug fix | 5/9 |
| Value-level taint, after bug fix | **7/9** |

The two lost documents are the designed trade-offs: (1) "forward the budget to finance@acme.example" holds the send because the address came
from the document, which is structurally the same as attack A10; (2) a security-training text quoting "ignore previous instructions" is blocked
by the detector (a known false positive).

## What the real run found (bugs fixed)
1. The first harness asked for one turn only, so the model never reached `send_email` and results were meaningless. Fixed with a real agent loop.
2. Provenance tracking treated any word followed by a colon ("Notes:") as an identifier, so ordinary summaries were held. Fixed; regression tests added.
3. The first fix tokenised on the wrong characters, so `to=cfo@acme.example` no longer matched `cfo@acme.example`; the arena caught it
   (policy-only attack success rose to 12.5%). Fixed; back to 0%.

## Caveats (state these out loud)
- 10 attacks, 9 harmless documents, 1-2 runs: a small sample. 9/20 vs 0/20 is a clear gap but not a precise rate.
- The attacks are ours, not independent. An independent attacker set is still missing.
- Haiku 5.5 resisted several attacks on its own (5 of 10 never succeeded even without Tripwire), so a stronger model may behave differently.
- Value-level taint is opt-in; the default session mode is safer but, as measured, blocks all legitimate model-initiated sends.
