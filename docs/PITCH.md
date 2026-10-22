# Pitch outline (10 slides, aligned to the judging rubric)

1. **Tripwire: don't trust the agent, verify it.** One line + the 100% -> 0% result.
2. **Problem (Problem & Impact 20%).** Agents read untrusted content and hold real powers. Cite OWASP LLM01 / LLM06 and any
   verifiable incident reports you find (add citations; do not use uncited numbers).
3. **Who hurts (validated segments).** Teams deploying tool-using agents (support, finance ops, dev tools). Add 3-5 interview quotes.
4. **Live demo part 1.** Attack succeeds unprotected; blocked with Tripwire (Presentation 10%).
5. **Live demo part 2.** The polite paraphrase the detector misses; structural policy still stops it. Show honesty.
6. **Architecture (Execution 15%).** Two independent layers + signed receipts.
7. **Arena + utility (Track Execution 25%).** 160 variants x defences: 100% -> 7.5% -> 0% attack success. The honest twist: session-wide
   taint stops the agent doing 7 of 8 legit tasks; value-level taint restores 7/8 with the same attacks stopped.
8. **Trust, safety, governance (15%).** Review queue fail-closed, threat model, system card, tamper-evident receipts, compliance alignment.
9. **Innovation (15%).** Taint-based agency control + self-attacking arena + verifiable receipts, in one small dependency-free core.
10. **Limits and roadmap.** Self-authored attack set, coarse taint, origin trust. Next: Bedrock attacker, KMS signing, fine-grained taint. Ask.

Tie-breakers to mention: container + health check (operational readiness); prompt-attack interception with measured numbers (security depth);
direct impact (agent actions needing human review: measured, e.g. 10 of 160 attack variants).
