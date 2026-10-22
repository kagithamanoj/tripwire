# HANDOFF: read this first when you pick the project back up

Last updated: 2026-10-22. Repo: github.com/kagithamanoj/tripwire (private). Folder: `Hackathons/tripwire`.

## Update (later on 2026-10-22)
Added since the first handoff: red-team of our own firewall (`docs/RED_TEAM_REPORT.md`: detector recall 29% -> 100% on a holdout, false positives
30% -> 0%, 5 bypasses fixed), persistent human approvals on AWS (live, tested end to end), 60 tests, redeployed. Approver token is generated in
Secrets Manager; fetch it with the command in `docs/DEPLOY_AWS.md`.

## Where things stand
- Code, tests (34), docs, CI: done and pushed. CI runs tests, secret scan, arena, utility, and builds+smoke-tests the Docker image.
- AWS: **deployed** in us-east-2 (stack `tripwire-demo`: Lambda Function URL, DynamoDB, KMS). Live URL is in `docs/DEPLOY_AWS.md`.
- Real-LLM (Bedrock) evaluation: **blocked** (details below). Everything else works without it.

## AWS credits status (earned $20 per task, up to $100)
- Done: Lambda web app (our deploy), cost budget (`tripwire-monthly-20usd`, created by Claude, **no email alert yet**), EC2 launch (t3.micro,
  launched then terminated), RDS database (db.t4g.micro, created then deleted). Manoj reported the credits page showed progress.
- Still to earn: **"Use a foundation model in the Bedrock playground"**: blocked until Bedrock access works (below).
- All temporary resources were deleted and verified (0 EC2 instances, 0 RDS, 0 stray secrets). Only stack `tripwire-demo` remains.
- To add an email alert: Billing -> Budgets -> `tripwire-monthly-20usd` -> Edit -> notifications.

## Bedrock status
- Account Bedrock token quota is **0** for Claude and Amazon Nova (every call returns throttling / "not available for this account").
- Manoj submitted 3 service-quota cases on 2026-10-22 (Sonnet, Haiku, Opus), status "Work in progress". Check Support -> Cases.
- Separately, Anthropic models need the **use case details form** submitted in the Bedrock console (Claude 4.x said so). Only Manoj can do it.
- Once approved: try the playground (also earns the credit), then run `scripts/live_eval.py`.

## Decision: fallback if Bedrock is not approved by 2026-10-23 10:00
Switch the **real-model evaluation** (not the whole project) to another provider. The AWS demo (Lambda/DynamoDB/KMS) stays as is.
Options, easiest first:
1. **Google Cloud (Vertex AI)**: new accounts get free-trial credit; Gemini models work without a quota request. Needs a small adapter
   like `tripwire/llm_agent.py` (function calling instead of Bedrock `toolUse`). Claude on Vertex needs Model Garden enablement and has quotas too.
2. **Anthropic API directly** with your own API key: no cloud quota, pay per token (cents). Same adapter shape.
Keep the gateway unchanged: any agent that returns `Call(tool, args, origin)` plugs in via `run_scenario(..., agent=...)`.
Whichever provider is used, report it honestly in `SYSTEM_CARD.md` and `AI_USAGE.md`.

## Do these first tomorrow (in order)
1. **Renew AWS login** (it lasts ~12h): `aws login --region us-east-2 --profile tripwire`
2. **Check the budget alarm exists** (Billing -> Budgets, $20) and look at Credits to see what they cover (`docs/COST.md`).
3. **Unblock Bedrock** (only you can do this; it is a form/agreement with your details):
   - Bedrock console (us-east-2) -> Model catalog -> pick an Anthropic Claude model -> submit the **Anthropic use case details** form.
   - Error seen: "Model use case details have not been submitted for this account" for Haiku 4.5, Sonnet 4.5, Sonnet 4.6.
   - Haiku 5.5 / Sonnet 5.5 said "not available for this account" (may need an access request, or be blocked by the org policy that also blocks App Runner).
     If so, use whichever Claude model works after the form.
   - Then run (needs `pip install -r requirements-aws.txt`, which includes `botocore[crt]` for `aws login` credentials):
     ```bash
     AWS_PROFILE=tripwire AWS_REGION=us-east-2 TRIPWIRE_MODEL_ID=<working id> python3 scripts/live_eval.py
     ```
     It writes `logs/live_eval.json`. Put the real numbers in README, SYSTEM_CARD, PITCH. Report them even if they look worse than the simulation.
4. **Meghana:** accept the GitHub invite (github.com/kagithamanoj/tripwire/invitations).

## Work that needs the two of you (cannot be done by Claude)
- 3-5 short interviews with people who build/deploy agents -> quotes for Problem & Impact (20% of score). Add to `docs/PITCH.md` slides 2-3.
- Complete and **sign** `docs/AI_USAGE.md` (list every AI tool used, honestly; Claude Code is listed).
- Register the team via the organizers' link (not given in the handbook). Ask organizers: any restrictions on GenAI tools? Standard declaration form?
  Does P-04 (working system) apply to SECURE? (We meet it anyway.)
- Review `docs/THREAT_MODEL.md` and `docs/SYSTEM_CARD.md` so you can defend every claim.
- Rehearse the 3-minute demo in `docs/PROJECT_GUIDE.md`.
- Before submitting: make the repo public, regenerate `logs/`, re-run `scripts/check_secrets.py`, re-check the live URL.
- After judging: `./scripts/destroy_aws.sh` to stop all AWS cost.

## Known issues / decisions
- Two early commits show author "Manoj Kumar" (older git name). Cosmetic; fixing needs another force-push.
- Demo URL is public with no login; the budget alarm is the cost backstop.
- AWS account id must never go in the repo (scripts read it at runtime).
- Claude co-author trailers were removed from history at your request; keep Claude Code declared in `AI_USAGE.md` regardless.

## Useful commands
```bash
python3 -m tripwire demo | eval | arena | utility | serve
python3 -m unittest discover -s tests -v
python3 scripts/check_secrets.py
./scripts/deploy_aws.sh      # redeploy after code changes
./scripts/destroy_aws.sh     # tear down everything
```

## Map of the docs
`docs/PROJECT_SUMMARY.md` (start here) -> `PROJECT_GUIDE.md` (plain-language + demo script) -> `ARCHITECTURE.md` -> `THREAT_MODEL.md`
-> `SYSTEM_CARD.md` -> `DEPLOY_AWS.md` -> `COST.md` -> `SELF_REVIEW.md` (honest ~75/100 score and gaps) -> `PITCH.md` -> `SUBMISSION_CHECKLIST.md`.
