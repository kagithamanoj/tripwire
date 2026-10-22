# Tripwire: project summary

**One line:** a firewall for AI agents that stops prompt-injection attacks from becoming real actions, and proves what it decided with
cryptographically signed receipts. Track: **SECURE**. Team: Manoj Kagitha, Meghana Alaparthy.

## The problem
AI agents read untrusted content (web pages, emails, files) and also hold real powers (send email, run code, move money). An attacker who
controls any content the agent reads can hide instructions in it. LLMs cannot reliably tell data from instructions, so the agent obeys.
That is prompt injection (OWASP LLM01) leading to excessive agency (LLM06).

## What Tripwire does (4 layers)
1. **Scan input.** Normalise text (strip invisible characters, fold look-alike letters, decode base64) and score it against injection rules.
2. **Control actions.** Track what the agent has read. A risky tool call needs a human (or is blocked) if any of its values came from untrusted
   content, whether or not the detector noticed the attack. Two modes: *session* (safest) and *value* (tracks which values are untrusted).
3. **Filter output.** Redact secrets; strip image links that could leak data.
4. **Prove it.** Every decision becomes a hash-chained receipt signed by an AWS KMS key; anyone can re-verify, and tampering is detected.

Plus a **red-team arena** that attacks the defences with 160 mutated injections and publishes the score.

## Measured results (reproduce with the commands in README)
| Defence | Attack success (160 variants) | Legit tasks done w/o human (8) | Attacks stopped in mixed tasks (3) |
|---|---|---|---|
| none | 100% | 8/8 | 0/3 |
| detector only | 7.5% | 8/8 | 1/3 |
| full, session taint | 0% | 1/8 | 3/3 |
| full, value taint | 0% | 7/8 | 3/3 |
Detector recall on the 16-attack seed set is 81.2% (misses 3, all paraphrases); false-positive rate 12.5% (1 of 8 benign, a security-training text).
**Honest caveats:** self-written attacks, simulated agent, small corpus. Not independent evidence. Real-LLM results are pending (see HANDOFF).

## What is built
- Python core, standard library only (no dependencies): detector, policy, gateway, receipts, review queue, arena, utility benchmark.
- Local CLI + web UI (`python3 -m tripwire demo|eval|arena|utility|serve`).
- AWS deployment (us-east-2): Lambda Function URL + DynamoDB + KMS via CloudFormation; live URL in `DEPLOY_AWS.md`.
- Docker image, built and smoke-tested in GitHub Actions CI. 34 unit tests, secret scan, CI.
- Bedrock real-LLM agent adapter + eval script (written, unit-tested with fakes, **not yet run live**).
- Docs: architecture, threat model (15 risks), system card, AI usage declaration, submission checklist, pitch outline, self-review, cost.

## What is still open
Real-LLM numbers (blocked on Bedrock access), user interviews, slide deck, persistent human-approval flow, AI declaration signatures,
team registration, making the repo public, rehearsal.
