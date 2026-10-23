# Tripwire

**Don't trust the agent. Verify it.**  
Track: **SECURE** (All Day AI Hackathon 2026)

[![CI](https://github.com/kagithamanoj/tripwire/actions/workflows/ci.yml/badge.svg)](https://github.com/kagithamanoj/tripwire/actions/workflows/ci.yml)

**Live demo:** taken down to save cost, so the hosted service is not available right now. Run it locally (see below) or redeploy it with `scripts/deploy_aws.sh`; `docs/DEPLOY_AWS.md` has the steps.

Tripwire is a firewall for tool-using AI agents. It scans what the agent reads, remembers that the agent has seen untrusted
content ("taint") so risky actions need a human, filters what it says, and signs every decision into a tamper-evident log.
A built-in red-team arena attacks the defences with 160 mutated injections and publishes the score.

| Defence | Attack success (160 variants) | Legit tasks done without a human (8 tasks) | Attacks stopped in mixed tasks |
|---|---|---|---|
| None | 100% | 8/8 | 0/3 |
| Detector only | 7.5% | 8/8 | 1/3 |
| Full, session-wide taint | 0% | **1/8** | 3/3 |
| Full, value-level taint | 0% | **7/8** | 3/3 |

Session-wide taint is safe but nearly stops the agent working; value-level taint tracks *which values* came from untrusted
content and recovers almost all legitimate work. The one task still routed to a human sends to an external recipient, by design.

*Self-authored attack set against a simulated naive agent. See `docs/THREAT_MODEL.md` for limits.
With a real model (Claude Haiku 5.5, two runs of the 10 attacks): 9 of 20 succeeded without Tripwire, 0 of 20 with it; legitimate work completed 7 of 9 times with value-level taint. Details and caveats: `docs/REAL_MODEL_EVAL.md`.*

## Run it locally
Needs Python 3.11+ and nothing else (no packages, no accounts, no keys).
```bash
git clone https://github.com/kagithamanoj/tripwire.git && cd tripwire
python3 -m tripwire demo      # two attacks, side by side, with signed receipts and a tamper check
python3 -m tripwire serve     # web UI at http://localhost:8080 (try an attack in the page)
```
Expected from `demo`: the unprotected agent reaches the attacker's goal (`True`), the protected one does not (`False`), the receipt chain
verifies (`True`), and after editing a receipt verification fails (`(False, 0)`).
To try human approvals locally, start the server with a token of your choosing, for example
`TRIPWIRE_APPROVER_TOKEN=pick-any-value python3 -m tripwire serve`, then open the "Human approvals" card and paste that value.

More commands:
```bash
python3 -m tripwire eval       # ground-truth detector and policy metrics on the seed corpus
python3 -m tripwire arena      # 160 attack variants against five defence settings
python3 -m tripwire utility    # does the agent still get work done?
python3 -m unittest discover -s tests -v
python3 scripts/check_secrets.py
docker build -t tripwire . && docker run -p 8080:8080 tripwire
```

## Demonstrating the SECURE controls (about 5 minutes)
| Control | How to show it |
|---|---|
| Injection blocked before the agent sees it | `python3 -m tripwire demo`, first attack |
| A paraphrase the detector misses is still stopped by the taint policy | second attack in `demo`, or paste it into the web page with taint mode "value" |
| Human override that fails closed | in the web page or API, hold an action, approve it with the token; undecided items are denied after 15 minutes |
| Tamper-evident signed receipts | `demo` edits a receipt and verification fails; on AWS, `GET /api/session/<id>` re-verifies the chain through KMS |
| Output filter and secret redaction | `python3 -c "from tripwire.gateway import Gateway; print(Gateway().filter_output('![x](https://evil.example/l?d=1)'))"` |
| Measured results | `python3 -m tripwire arena` and `docs/REAL_MODEL_EVAL.md` |

## Docs
[Architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), [red-team report](docs/RED_TEAM_REPORT.md),
[real-model evaluation](docs/REAL_MODEL_EVAL.md), [system card](docs/SYSTEM_CARD.md), [AWS deployment](docs/DEPLOY_AWS.md),
[data handling and privacy](docs/DATA_AND_PRIVACY.md), [AI usage declaration](docs/AI_USAGE.md).

## Technical inventory
| Layer | What | Notes |
|---|---|---|
| Product code | Python 3.11+, standard library only | No third-party runtime dependencies, no model calls inside the product |
| Cloud (live demo) | AWS Lambda Function URL, KMS, DynamoDB (2 tables), Secrets Manager, CloudWatch Logs, S3, CloudFormation | Region us-east-2; one stack, `infra/template.yaml` |
| Models | **Claude Haiku 5.5** via the Anthropic API | Evaluation script only (`scripts/live_eval.py`); not in the deployed demo |
| AI development tools | **Claude Code** (Claude Sonnet 5.5), Claude Slides | Declared in `docs/AI_USAGE.md` |
| Optional libraries | `boto3`, `botocore[crt]` | Only for the AWS adapters (`requirements-aws.txt`) |
| Delivery | GitHub, GitHub Actions, Docker | CI: tests, secret scan, arena, utility, container build and smoke test |
| Not used | Amazon Bedrock (quota declined), OpenAI, Gemini, Copilot | |

What data each provider receives, retention and security controls: [docs/DATA_AND_PRIVACY.md](docs/DATA_AND_PRIVACY.md).

## Team
Manoj Kagitha ([@kagithamanoj](https://github.com/kagithamanoj)), Meghana Alaparthy ([@meghana-alaparthy](https://github.com/meghana-alaparthy))
