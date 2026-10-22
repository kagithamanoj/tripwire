# Deploying Tripwire on AWS

**Status: plan only. Nothing here has been run or tested yet.** The app itself is verified locally; the AWS wiring is the next milestone.

## Phase 0: account setup (Manoj + Meghana)
1. Create an AWS account (one owner), enable MFA on the root user, then create an IAM Identity Center or IAM admin user for daily use. Never use root keys.
2. Set a **billing budget alarm** (e.g. $20) in AWS Budgets before anything else.
3. Install AWS CLI v2 and run `aws configure sso` (preferred) so no long-lived keys are stored. Never commit credentials (P-07).
4. Pick one region (suggest `us-east-1`; check Bedrock model access for your chosen model in that region).

## Phase 1: minimum live URL (about 1 hour, low cost)
Container to ECR, run on **AWS App Runner**.
```bash
aws ecr create-repository --repository-name tripwire
docker build -t tripwire .
# tag + push to <account>.dkr.ecr.<region>.amazonaws.com/tripwire:latest  (ecr get-login-password | docker login ...)
# App Runner: create service from the ECR image, port 8080, health check /healthz
```
This gives the live URL for the judges. The demo has no auth, so keep it to demo data and consider enabling App Runner's
private endpoint or putting AWS WAF rate limiting in front.

## Phase 2: production-shaped features
| Feature | AWS service | Code change |
|---|---|---|
| Unforgeable receipts | KMS asymmetric key (ECDSA) | New `KmsSigner` with same `sign(hex)` interface; verify with public key |
| Durable receipts + queue | DynamoDB (TTL for retention) | Storage adapter for `ReceiptLog` and `ReviewQueue` |
| Approvals | SNS to email/Slack, approve link | Endpoint calling `Gateway.resolve` |
| Independent attacker / real agent | Bedrock (Claude) | Extra variant generator in `arena.py`; real agent behind the gateway |
| Observability | CloudWatch alarms on block/review rate | Emit metrics from gateway |
| Infrastructure as code | CDK (Python) | `infra/` stack (not written yet) |

## Cost and safety notes
App Runner idles cheaply but is not free; delete the service after judging. Bedrock is pay per token; cap the arena's LLM calls.
Do not expose the demo server without rate limiting.
