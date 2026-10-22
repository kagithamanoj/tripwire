# Data handling, privacy, retention and security controls

Written in response to the judges' request to document what data goes to each provider. Facts below describe what this repository and its
deployment actually do. Where a provider's own policy governs (retention, training), we link to the policy instead of restating numbers.

## Services and models in use

| Component | Provider | Purpose | Where it runs |
|---|---|---|---|
| Tripwire core (Python standard library only) | us | Detector, taint policy, gateway, receipts, review queue, arena | Local, Docker, AWS Lambda |
| AWS Lambda + Function URL | Amazon Web Services | Hosts the live demo and API | us-east-2 |
| AWS KMS (asymmetric ECC P-256 key) | Amazon Web Services | Signs every receipt; verifies signatures | us-east-2 |
| Amazon DynamoDB (two tables) | Amazon Web Services | Stores receipts and held actions | us-east-2 |
| AWS Secrets Manager | Amazon Web Services | Holds the approver token | us-east-2 |
| Amazon CloudWatch Logs | Amazon Web Services | Lambda error logs, 14-day retention | us-east-2 |
| Amazon S3 (one bucket, public access blocked) | Amazon Web Services | Holds the deployment package only | us-east-2 |
| AWS CloudFormation | Amazon Web Services | Deploys the stack (`infra/template.yaml`) | us-east-2 |
| Claude Haiku 5.5 (`claude-haiku-5-5`) via the Anthropic API | Anthropic | **Evaluation only**: acts as the agent under test in `scripts/live_eval.py` | Called from a developer's machine |
| Claude Code (model Claude Sonnet 5.5) | Anthropic | **Development tool** that helped write the code and docs (see `AI_USAGE.md`) | Developer's machine |
| GitHub and GitHub Actions | GitHub | Source hosting; CI runs tests, secret scan and a container build | GitHub |

Not used: Amazon Bedrock (attempted; AWS declined the quota), OpenAI, Google, or any model inside the deployed demo.
Optional libraries (`requirements-aws.txt`): `boto3`, `botocore[crt]`, needed only for the AWS adapters.

## What data goes where

**1. Live demo on AWS.** A visitor can post text to `/api/try` (body capped at 64 KB, text capped at 20,000 characters).
- It is processed in the Lambda's memory by our own rules. **It is never sent to any model or any third party.**
- **Stored in DynamoDB receipts:** event metadata only (source label, decision, score, rule IDs, tool name, risk, a review ID). No document text and no tool arguments. Retention: 90 days (DynamoDB TTL).
- **Stored in DynamoDB reviews (only when an action is held for a human):** the tool name and its arguments, and for held content a 120-character excerpt, so a person can judge it. Retention: 7 days (TTL). Items not decided within 15 minutes are denied.
- **Logs:** our code logs only unhandled-error tracebacks, not request bodies. CloudWatch retention: 14 days.
- Please do not submit personal data to the demo. It is intended for synthetic text. Our code does not store IP addresses; AWS infrastructure handles request metadata under its own terms.

**2. Real-model evaluation (`scripts/live_eval.py`, local only, not part of the deployment).**
- **Sent to Anthropic:** our own attack and benign sample documents (from `tripwire/corpus.py`), the task sentence, and the simulated tool results ("ok", "held", "blocked").
- **Not sent:** personal data, customer data, AWS data, receipts, or any credential other than the API key used to authenticate the request.
- The API key is read from an environment variable at run time. It is never printed, logged or written to a file by our code.
- Provider retention and training policies are Anthropic's; we did not configure any special retention or zero-retention arrangement. See Anthropic's current commercial terms and privacy policy.

**3. Development with an AI coding assistant.** Prompts, repository files and command output from the development sessions were processed by Anthropic's service. See `AI_USAGE.md`. No customer or personal data was involved.

**4. GitHub.** Source code, docs and CI logs. The repository is public; it contains no keys or account identifiers (verified by `scripts/check_secrets.py`, which also runs in CI, and by a scan of the full commit history).

## Retention summary

| Data | Where | Retention |
|---|---|---|
| Receipts (metadata only) | DynamoDB | 90 days, then TTL expiry |
| Held actions and excerpts | DynamoDB | 7 days, then TTL expiry; undecided after 15 minutes = denied |
| Lambda error logs | CloudWatch Logs | 14 days |
| Deployment package | S3 | Until the stack is torn down (`scripts/destroy_aws.sh` deletes it) |
| Approver token | Secrets Manager | Until the stack is deleted |
| Evaluation prompts | Anthropic API | Governed by Anthropic's policy |
| Development sessions | Anthropic (Claude Code) | Governed by Anthropic's policy |

## Security controls

- **No secrets in the repo.** Secret patterns (AWS, Anthropic, GitHub, Slack, Google, JWT, private keys) are scanned in every CI run and across history.
- **Signing key never leaves KMS.** Receipts are hash-chained and signed; editing or deleting one fails verification. The Lambda role may only call `kms:Sign` and `kms:Verify` on that key.
- **Least-privilege IAM.** One role with access to one key, two tables and one secret, plus basic logging.
- **Encryption.** In transit: HTTPS for the Function URL and the Anthropic API. At rest: DynamoDB and Secrets Manager use AWS's default encryption; the S3 bucket blocks all public access.
- **Human override that fails closed.** Approvals need a token from Secrets Manager (compared in constant time); undecided items expire to deny; a late approval is refused; every decision is signed into the original receipt chain.
- **Input and error handling.** Size limits on request bodies and text; malformed requests get 4xx; internal errors return a generic 500 with details only in the logs.
- **Egress and secret controls in the product.** Allowlisted destinations, secret detection in tool arguments, and output redaction of secrets and image/HTML beacons.

## Incident note (disclosed for transparency)
During the real-model run, an Anthropic API key was displayed in a terminal window, which made it visible to the AI coding session. It was revoked the same day. No key was ever written to the repository or its history.

## Known limits
- The demo endpoints are public and unauthenticated by design; abuse is bounded by AWS cost, with a budget alarm as the backstop.
- Approver access is one shared token; production use needs per-person identity (for example Cognito or IAM).
- We do not control the providers' retention; teams with stricter needs should configure their own provider agreements.
