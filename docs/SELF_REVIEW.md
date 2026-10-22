# Self-review as a judge (v0.1)

Scored against the handbook rubric. Estimated total **~68/100**. Not a prediction of the real result.

| Criterion | Weight | Score | Gap to close |
|---|---|---|---|
| Problem & Impact | 20 | 11 | 3-5 real interviews with people who build agents; cite OWASP LLM01/LLM06 and verifiable incident reports; define a target metric |
| Track Execution | 25 | 17 | Wrap a **real LLM agent** (Bedrock) behind the gateway; independent attacker; held-out attack set |
| Innovation | 15 | 10 | Finer-grained taint (per-value data flow) so safe actions stop needing review; that is the novel step |
| Trust, Safety, Governance | 15 | 13 | Run the approval flow with real people; measure approval fatigue |
| Technical Depth | 15 | 11 | CI (added), IaC for AWS, KMS signer, DynamoDB adapters, deployed URL |
| Presentation & Demo | 10 | 6 | Slide deck, rehearsed 3-minute demo, polished web UI |

## Update (v0.2)
Added: value-level taint (7/8 legit tasks vs 1/8 with session taint, same 3/3 attacks stopped), utility benchmark,
Bedrock agent adapter (unit-tested with a fake client; **not run against the real service**), 29 tests.
Still open: real-LLM results, user interviews, AWS deployment, deck. Estimated total now ~72/100.

## Update (v0.3)
Deployed on AWS (Lambda + DynamoDB + KMS) with a public demo URL; receipts are KMS-signed and re-verifiable from DynamoDB; 34 tests;
CI builds and smoke-tests the container. Still open: real-LLM (Bedrock) results, user interviews, deck. Estimated ~75/100.

## Update (v0.4, end of 2026-10-22)
Rescored as a skeptical judge: Problem and Impact 11/20 (no interviews yet), Track Execution 19/25, Innovation 11/15, Trust/Safety/Governance 14/15,
Technical Depth 13/15, Presentation 7/10 (deck done, not rehearsed). **About 75/100.** Not a 10/10, and nothing we can do tonight honestly makes it one.
What moves it most: 3-5 real user interviews (+5 to +7), real-model results (+2 to +3), a rehearsed demo (+1 to +2).
Done this round: red-team of our own firewall (docs/RED_TEAM_REPORT.md), persistent signed human approvals on AWS, 60 tests, pitch deck.

## Update (v0.5, real-model results)
Real model (Claude Haiku 5.5): 9/20 attacks succeed without Tripwire, 0/20 with it; legitimate work 7/9 with value taint (0/9 with session taint).
The real run also exposed two provenance bugs (fixed). Still open: user interviews, an independent attacker set, a rehearsed demo. About 77/100.

## Honest critique
1. **Circular evaluation.** Attacks, defence and the naive agent were written by the same author. Results are a regression benchmark, not independent evidence.
2. **0% attack success is partly structural.** Coarse taint blocks all risky tool calls after any untrusted read. The meaningful number is the **utility cost**, which is under-measured (8 benign documents).
3. **Detector recall** on the post-build holdout set went 29.2% -> 100% with false positives 30% -> 0% after fixes; that set is now tuned against, so treat the after numbers as optimistic (see `docs/RED_TEAM_REPORT.md`).
4. **Mostly simulated.** The arena uses a scripted agent; a real model was run on only 10 attacks and 9 harmless documents (docs/REAL_MODEL_EVAL.md). Tools never have real side effects.
5. **Origin labelling is trusted** from the host app (threat T11).
6. **Demo endpoint is public and unauthenticated** (deployed on AWS; see `DEPLOY_AWS.md` limits).
7. **No user validation** of the problem.

## Update (v0.4, submission day)
Persistent human approvals are live on AWS (DynamoDB reviews table, approver token in Secrets Manager, KMS-signed decisions, 15-minute fail-closed timeout);
60 tests, CI green on main, live demo URL verified working; pitch deck built (`docs/deck/tripwire-pitch.pptx`).
Still open: real-LLM (Bedrock) results (AWS quota cases pending; only the account owner can file the use-case form), user interviews,
AI_USAGE signatures, making the repo public at submission. Estimated total now ~78/100. The circular-evaluation critique above still stands and remains the main gap.

## Priority fixes (highest judged value first)
1. Real LLM agent via Bedrock behind the gateway + LLM attacker, report held-out numbers.
2. Utility benchmark (task completion with and without Tripwire) and finer-grained taint to cut review load.
3. User interviews (Problem & Impact).
4. Deploy on AWS (App Runner), then KMS signing.
5. Deck + rehearsed demo.
