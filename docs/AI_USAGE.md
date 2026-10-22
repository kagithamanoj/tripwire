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

**Manoj Kagitha**
- Decided to build this project and chose the SECURE track. The idea (a firewall for tool-using agents) was proposed by Claude from the handbook; Manoj chose it, pushed for a stronger version, and rejected weaker alternatives.
- Directed the build session by session: set the scope, approved or declined each action (deployments, pushes, history changes), and reviewed output before it was pushed. Corrected course several times, for example on commit attribution, which notes stay in the repo, and the declaration wording.
- Asked Claude to attack its own firewall and to score the project honestly, then directed the fixes that followed (stronger detector, five bypass fixes, the provenance fix in the policy engine). Claude carried out the red-team work.
- Ran the real-model evaluation himself, in his own terminal with his own Anthropic API key, and reported the results back; he chose the Anthropic API when AWS declined the Bedrock quota.
- Owned the accounts and outside actions: set up the AWS account, owns the Anthropic account and API key, signed in to AWS, filed three Bedrock quota cases, submitted the Anthropic use-case form and Marketplace subscriptions, approved the AWS deployment, and revoked the API key after the run.
- Asked the organizers and judges about provider restrictions, the declaration form and the live-demo requirement, and acted on their answers.
- Approved the pushes to the repositories, read this declaration, and signed it.

**Meghana Alaparthy**
- Second team member. Read and agreed to this declaration before it was signed, and has collaborator access to the repository.

**What Claude did, for comparison:** wrote the code, tests, infrastructure template, scripts and documents; proposed the design rules (no model in the enforcement path, policy decides, fail closed, human approval for risky or external actions); and ran the red-team analysis, the arena and the test runs when asked. Verification came from running the code: 70 tests, the evaluation, the 160-variant arena, the utility benchmark, the secret scan, the real-model run and the live AWS demo.

## Declaration
We declare that the above is a complete and accurate account of generative-AI and automated coding tools used in this project.

| Name | GitHub | Signature | Date |
|---|---|---|---|
| Manoj Kagitha | @kagithamanoj | Manoj Kagitha (typed signature) | 2026-10-22 |
| Meghana Alaparthy | @meghana-alaparthy | Meghana Alaparthy (typed signature) | 2026-10-22 |
