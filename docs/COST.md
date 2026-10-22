# Cost: what costs money and will the credits cover it?

Short answer: the deployed stack should cost **roughly $1-3/month**, almost all of it the KMS key. Your $100 credits should cover that
if they apply to KMS/Lambda/DynamoDB (most AWS credits do). **Check, don't assume:** Billing console -> Credits -> look at the
"eligible services/exclusions" text. I could not read the credit terms from the CLI.

| Resource | Pricing model | Expected at demo traffic |
|---|---|---|
| Lambda | 1M requests + 400k GB-s free every month (permanent free tier) | $0 |
| Lambda Function URL | no extra charge | $0 |
| DynamoDB on-demand | per request; 25 GB storage free | cents |
| KMS asymmetric key | about $1/month per key + about $0.03 per 10k requests | about $1/month (the main cost) |
| CloudWatch Logs | per GB ingested/stored, 14-day retention | cents |
| S3 artifact bucket | per GB | well under $0.10 |
| Bedrock Claude (only when you run the real-model eval) | per input/output token | cents for ~20 short calls; **may not be covered by credits** |

## Things that could surprise you
- **The public URL has no login.** Someone hammering it would raise Lambda/DynamoDB usage. Free tier absorbs a lot, and the budget alarm is the
  backstop. Make sure you created the $20 budget alarm (Billing -> Budgets).
- **KMS keys keep billing until deleted.** `scripts/destroy_aws.sh` removes the stack; KMS then schedules key deletion (7-30 day window),
  and billing stops once the key is deleted.
- **Bedrock third-party (Anthropic) models:** credit programs often exclude AWS Marketplace / third-party model usage. Unknown for your account.
  Run a handful of calls first and look at Cost Explorer the next day.
- **Credits expire** (yours: 180 days) and some programs apply them only after free-tier usage.

## How to see real spend
Billing -> Bills (by service), Cost Explorer (daily, appears after about 24 hours), and Credits (balance). All free to view in the console.
