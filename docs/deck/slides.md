# Tripwire pitch deck - slide text source

Edit here, then rebuild `tripwire-pitch.pptx`. Numbers verified by running the code on 2026-10-22.

## 1. TRIPWIRE
- Don't trust the agent. Verify it.
- A firewall for tool-using AI agents.
- SECURE track - All Day AI Hackathon 2026
- Manoj Kagitha - Meghana Alaparthy

## 2. The problem
- AI agents read untrusted content and hold real powers: send email, run code, move data.
- One poisoned document can turn the agent into the attacker's hands.
- OWASP Top 10 for LLM Applications 2025: LLM01 prompt injection, LLM02 sensitive information disclosure, LLM06 excessive agency.
- Measured baseline: an unprotected agent carried out the attack in 100% of our scenarios.

## 3. Who it hurts
- Teams deploying tool-using agents: support copilots, finance operations, developer tools.
- Today they cannot audit what the agent read, what it decided, or what it sent.
- PLACEHOLDER: add 3-5 one-line quotes from agent builders interviewed on event day.
- Target: every high-risk agent action is either provably safe or seen by a human first.

## 4. Live demo
- The attack succeeds with no protection. The same attack is blocked with Tripwire on.
- Signed receipts show every decision, and the chain re-verifies on demand.
- Live: qtu25iuq5qyc72x642eofcef2a0bbogo.lambda-url.us-east-2.on.aws
- Local: python3 -m tripwire demo

## 5. The honest twist
- A polite paraphrase has no attack keywords. The detector misses it, and we say so.
- The structural policy layer still stops it: values that came from untrusted content cannot drive high-risk actions without a human.
- Detection is a signal. Policy is the wall.

## 6. How it works
- 1. Ingest scan: everything the agent reads is checked and labelled by origin.
- 2. Value-level taint: the system remembers which values came from untrusted content.
- 3. Policy gate: risky actions using tainted values stop for a human. Approvals fail closed.
- 4. Output filter and signed receipts: what leaves is checked; every decision is KMS-signed into a tamper-evident chain.
- Python standard library only. Deployed on AWS Lambda, DynamoDB and KMS.

## 7. Measured results
- Red-team arena, 160 mutated injections (self-authored set):
- No defence: attack success 100%, legit tasks 8 of 8, mixed attacks stopped 0 of 3
- Detector only: attack success 7.5%, legit tasks 8 of 8, mixed attacks stopped 1 of 3
- Full, session-wide taint: attack success 0%, legit tasks 1 of 8, mixed attacks stopped 3 of 3
- Full, value-level taint: attack success 0%, legit tasks 7 of 8, mixed attacks stopped 3 of 3
- Session-wide taint is safe but stops the work. Value-level taint recovers it.

## 8. We red-teamed ourselves
- Holdout attacks written after the defence existed: detector recall 29% to 100%, false positives 30% to 0%.
- That set is now tuned against, so treat the after numbers as optimistic. We publish both.
- 5 real bypasses found and fixed: multi-recipient egress, missed secret formats, output beacons, oversized input, Lambda error handling.
- 60 tests passing. CI green. Secret scan: 0 findings.

## 9. Trust, safety, governance
- Threat model and AI system card in the repo, with stated limits.
- Human approvals are persistent (DynamoDB) and fail closed: undecided in 15 minutes means denied.
- Every decision is a KMS-signed receipt in a tamper-evident chain that anyone can re-verify.
- Signed AI-usage declaration: what the tools did, what the humans did.

## 10. Limits and roadmap
- Honest limits: the attack set is self-authored; the real-LLM evaluation on Amazon Bedrock is implemented but blocked on an AWS quota approval.
- Next: independent attacker, per-person approver identity, WAF on the demo endpoint.
- The ask: put a verification layer in front of every production agent.
