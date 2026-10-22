#!/usr/bin/env bash
# Deploy Tripwire to AWS (Lambda + DynamoDB + KMS). Needs: aws login --profile tripwire
set -euo pipefail
cd "$(dirname "$0")/.."

export AWS_PROFILE="${AWS_PROFILE:-tripwire}" AWS_REGION="${AWS_REGION:-us-east-2}" AWS_DEFAULT_REGION="${AWS_REGION:-us-east-2}"
STACK="${STACK:-tripwire-demo}"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
BUCKET="tripwire-artifacts-${ACCOUNT}-${AWS_REGION}"

if ! aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
  aws s3api create-bucket --bucket "$BUCKET" --region "$AWS_REGION" \
    --create-bucket-configuration "LocationConstraint=${AWS_REGION}" >/dev/null
  aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
fi

rm -rf build && mkdir -p build/lambda
cp -R tripwire build/lambda/
find build -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
find build -name '._*' -delete

aws cloudformation package --template-file infra/template.yaml \
  --s3-bucket "$BUCKET" --output-template-file build/packaged.yaml >/dev/null
aws cloudformation deploy --template-file build/packaged.yaml \
  --stack-name "$STACK" --capabilities CAPABILITY_IAM --no-fail-on-empty-changeset

aws cloudformation describe-stacks --stack-name "$STACK" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output text
