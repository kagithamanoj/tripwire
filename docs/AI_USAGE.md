# AI Tool Usage Declaration (P-05)

**Project:** Tripwire. **Track:** SECURE.

## Tools used
| Tool | Used for | Human review |
|---|---|---|
| Claude Code (Anthropic), model Claude Sonnet 5.5 | Drafted the initial codebase, tests and documentation in this repository | Team reviewed output; metrics were produced by running the code, not by the model's claims |

Update this table honestly if you use any other GenAI or code-completion tool (Copilot, ChatGPT, Bedrock, image generators, etc.).

## Runtime AI
The shipped product contains no LLM calls. The evaluation script `scripts/live_eval.py` calls the Anthropic API (model `claude-haiku-5-5`) to act as the agent under test; it needs the operator's own API key from an environment variable and is not part of the deployed demo. Amazon Bedrock was attempted but AWS declined the quota, so it was not used.

## What the humans did
- Problem selection and track: Manoj chose the problem (a firewall for tool-using agents) and the SECURE track; Meghana Alaparthy is the second team member.
- Direction: Manoj directed the build session by session (scope, the red-team pass on our own firewall, the AWS deployment, the decision to run the real-model evaluation through the Anthropic API when AWS declined the Bedrock quota) and reviewed all output before it was pushed.
- Accounts and approvals: Manoj owns the AWS account work (deployment approvals, the monthly budget alarm, three Bedrock service-quota cases filed Oct 22, teardown plan) and the GitHub repositories.
- Verification: the metrics in the README and pitch come from running the code (60 tests, eval, arena, utility benchmark, live demo), not from model claims.
- Meghana's own additions to this section: to be appended by her before submission.

## Declaration
We declare that the above is a complete account of generative-AI and automated coding tools used in this project.

| Name | GitHub | Signature | Date |
|---|---|---|---|
| Manoj Kagitha | @kagithamanoj | Manoj Kagitha (typed) | 2026-10-22 |
| Meghana Alaparthy | @meghana-alaparthy | Meghana Alaparthy (typed) | 2026-10-22 |
