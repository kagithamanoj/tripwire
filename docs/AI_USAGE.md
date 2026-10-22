# AI Tool Usage Declaration (P-05)

**Project:** Tripwire. **Track:** SECURE. **Revised:** 2026-10-22, after judge feedback asked for a complete list of tools and uses.
Because the content below changed, earlier signatures no longer apply. Each team member should read it and sign in the table at the end.

## Generative-AI and automated tools used

| Tool | Provider / model | What it was used for | Human oversight |
|---|---|---|---|
| Claude Code | Anthropic, model Claude Sonnet 5.5 | Wrote most of the code, tests, CloudFormation template, deployment scripts and documentation in this repository; ran tests; carried out AWS CLI and GitHub operations at the team's direction | Manoj directed each step and approved actions; results (metrics, test runs, live checks) come from running the code, not from the model's statements |
| Claude (Slides feature of the Claude desktop app) | Anthropic | Drafted the 12-slide pitch deck from the project's measured results | Team reviews and edits the deck before presenting |
| Claude (second coding session) | Anthropic | Produced an earlier PowerPoint draft of the deck and some submission-day notes; neither is part of this repository now | Team reviewed before use |
| Claude Haiku 5.5 (`claude-haiku-5-5`) via the Anthropic API | Anthropic | **Evaluation only**: acts as the agent under test in `scripts/live_eval.py` | Run by a team member with their own API key; not part of the deployed demo |
| Claude sub-agent (attack authoring attempt) | Anthropic | Was asked to write an independent set of attack documents. A safety control stopped it partway; **nothing from it was used** | Output discarded |
| GitHub Actions | GitHub (not generative AI) | Automated CI: tests, secret scan, container build | Team reads results |
| AWS CLI and CloudFormation | Amazon Web Services (not generative AI) | Automated deployment of the live demo | Team approved deployments |

**Not used:** GitHub Copilot, ChatGPT or other OpenAI models, Google Gemini, Amazon Bedrock (attempted; AWS declined the quota), image generators.
The deployed product contains **no model calls**; the live demo is deterministic Python.

**Data sent to the AI providers** is described in `docs/DATA_AND_PRIVACY.md`.

## What the humans did
- Problem selection and track: Manoj chose the problem (a firewall for tool-using agents) and the SECURE track; Meghana Alaparthy is the second team member.
- Direction: Manoj directed the build session by session (scope, the red-team pass on our own firewall, the AWS deployment, the decision to run the real-model evaluation through the Anthropic API when AWS declined the Bedrock quota) and reviewed all output before it was pushed.
- Accounts and approvals: Manoj owns the AWS account work (deployment approvals, the monthly budget alarm, three Bedrock service-quota cases filed Oct 22, teardown plan), the Anthropic account and API key, and the GitHub repositories.
- Verification: the metrics in the README and pitch come from running the code (70 tests, eval, arena, utility benchmark, real-model run, live demo), not from model claims.
- Meghana's own additions to this section: to be appended by her before submission.

## Declaration
We declare that the above is a complete and accurate account of generative-AI and automated coding tools used in this project.

| Name | GitHub | Signature | Date |
|---|---|---|---|
| Manoj Kagitha | @kagithamanoj | Manoj Kagitha (typed signature) | 2026-10-22 |
| Meghana Alaparthy | @meghana-alaparthy | Meghana Alaparthy (typed signature) | 2026-10-22 |
