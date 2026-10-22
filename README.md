# Tripwire

**Don't trust the agent. Verify it.**  
Track: **SECURE** (All Day AI Hackathon 2026)

Tripwire is a firewall for tool-using AI agents. It scans what the agent reads, remembers that the agent has seen untrusted
content ("taint") so risky actions need a human, filters what it says, and signs every decision into a tamper-evident log.
A built-in red-team arena attacks the defences with 160 mutated injections and publishes the score.

| Defence | Attack success (160 variants) |
|---|---|
| None | 100% |
| Detector only | 6.2% |
| Taint policy only | 0% |
| Full Tripwire | 0% (10 held for a human) |

*Self-authored attack set against a simulated naive agent. See `docs/THREAT_MODEL.md` for limits.*

## Quick start (Python 3.11+, no dependencies)
```bash
python3 -m tripwire demo
python3 -m tripwire eval
python3 -m tripwire arena
python3 -m tripwire serve        # http://localhost:8080
python3 -m unittest discover -s tests -v
python3 scripts/check_secrets.py
docker build -t tripwire . && docker run -p 8080:8080 tripwire
```

## Docs
Start with [docs/PROJECT_GUIDE.md](docs/PROJECT_GUIDE.md), then [ARCHITECTURE](docs/ARCHITECTURE.md),
[THREAT_MODEL](docs/THREAT_MODEL.md), [SYSTEM_CARD](docs/SYSTEM_CARD.md), [DEPLOY_AWS](docs/DEPLOY_AWS.md),
[SUBMISSION_CHECKLIST](docs/SUBMISSION_CHECKLIST.md), [PITCH](docs/PITCH.md), [AI_USAGE](docs/AI_USAGE.md).

## Technical inventory
Python standard library only. No third-party packages, no ML models, no API keys. Optional future: Amazon Bedrock, KMS, DynamoDB.

## Team
Manoj Kagitha ([@kagithamanoj](https://github.com/kagithamanoj)), Meghana Alaparthy ([@meghana-alaparthy](https://github.com/meghana-alaparthy))
