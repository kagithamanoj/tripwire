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

## Honest critique
1. **Circular evaluation.** Attacks, defence and the naive agent were written by the same author. Results are a regression benchmark, not independent evidence.
2. **0% attack success is partly structural.** Coarse taint blocks all risky tool calls after any untrusted read. The meaningful number is the **utility cost**, which is under-measured (8 benign documents).
3. **Detector recall is 81.2%** with a known false positive on security-training text.
4. **Simulated agent and tools.** No real LLM, no real side effects.
5. **Origin labelling is trusted** from the host app (threat T11).
6. **Nothing deployed.** AWS plan is untested.
7. **No user validation** of the problem.

## Priority fixes (highest judged value first)
1. Real LLM agent via Bedrock behind the gateway + LLM attacker, report held-out numbers.
2. Utility benchmark (task completion with and without Tripwire) and finer-grained taint to cut review load.
3. User interviews (Problem & Impact).
4. Deploy on AWS (App Runner), then KMS signing.
5. Deck + rehearsed demo.
