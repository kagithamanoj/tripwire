# Red-team report: we attacked our own firewall

Date: 2026-10-22. Method: after the first build, we wrote attacks and tricky benign text we had **not** designed the defence for, recorded the
results *before changing anything* (`logs/holdout_before.json`), fixed what broke, and re-measured (`logs/holdout_after.json`).
Everything is reproducible: `python3 -c "from tripwire.holdout import run_holdout; print(run_holdout())"` and `tests/test_adversarial.py`.

## 1. Detector holdout (24 obfuscation/language variants of one attack; 20 hard benign texts; 4 paraphrases)
| Metric | Before | After |
|---|---|---|
| Recall on 24 variants | **29.2%** (7/24) | **100%** (24/24) |
| False positives on 20 hard benign texts | **30%** (6/20) | **0%** (0/20) |
| Paraphrases caught (no keyword overlap) | 0/4 | 0/4 (**known gap, by design**: the policy layer must stop these) |

What was missed at first: rot13, hex, URL-encoding, HTML entities, leetspeak, spaced or hyphenated letters, invisible Unicode "tag"
characters (ASCII smuggling), Greek look-alikes, double base64, and Spanish/French/German/Portuguese/Russian/Chinese/Japanese phrasings.
What was wrongly flagged: "System: Linux...", Android "developer mode", "You are now ready...", "admin mode" in code, benign runbooks.
Fixes: more decoders and reading variants, a spacing-insensitive check, tag-character decoding, multilingual rules, and narrower/lower-weight weak signals.

**Caveat (important):** these are now tuned against. Treat the "after" numbers as optimistic; a fresh set will score lower. Detector-only attack
success in the arena rose from 6.2% to 7.5% because lowering a weak "SYSTEM:" weight (to remove false positives) let a few attacks pass the
detector. The policy layer still stops them (full Tripwire: 0%).

## 2. Gateway bypasses found by probing, and fixed
| # | Bypass | Severity | Fix | Test |
|---|---|---|---|---|
| 1 | `to="b@evil.example, a@acme.example"` was **allowed**: only the last address was checked | High (exfiltration) | Check **every** email/URL host in the argument; all must be allowlisted | `TestEgressParsing` |
| 2 | Secrets not detected: GitHub, Slack, Google API, JWT, Bearer tokens, `sk-ant-` keys | Medium | Added 8 patterns (policy + repo scanner) | `TestSecrets` |
| 3 | Output filter missed reference-style Markdown images and HTML `<img>/<iframe>/<script>` beacons | Medium | Strip non-allowlisted embeds and dangling definitions | `TestOutputFilter` |
| 4 | Oversized input would be scanned partially or slowly | Medium | Over 200,000 chars: no partial scan, held for human review (fail closed) | `TestRobustness` |
| 5 | Lambda crashed (500 + stack) on odd events/bodies | Low | 400 for bad shapes/bodies; generic 500, details only in CloudWatch | `TestLambdaHardening` |

Also verified: 2,000 random-Unicode fuzz inputs never crashed the detector or filter; scans of 150k-char hostile inputs take about 0.1-0.3 s.

## 3. Still open (be upfront)
- Paraphrase attacks evade the detector entirely (no keyword overlap). Only the structural policy layer protects against them.
- Value-level taint can miss a high-risk call whose arguments never appeared in the document (T15).
- Attack and benign sets are self-authored; no independent attacker yet. A real-model run (Haiku 5.5) is in `docs/REAL_MODEL_EVAL.md`; it also found two provenance-tracking bugs, now fixed.
- Secrets in non-obvious encodings (base64-wrapped, split across arguments) are not detected.
- The review queue approval flow on AWS is now persisted (fixed after this report): reviews live in a DynamoDB table, the approver token sits in Secrets Manager, and decisions are appended to the session's KMS-signed chain. See `docs/DEPLOY_AWS.md`.
