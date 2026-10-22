#!/usr/bin/env bash
# Delete everything deploy_aws.sh created. Run after the hackathon to stop all costs.
set -euo pipefail
export AWS_PROFILE="${AWS_PROFILE:-tripwire}" AWS_REGION="${AWS_REGION:-us-east-2}" AWS_DEFAULT_REGION="${AWS_REGION:-us-east-2}"
STACK="${STACK:-tripwire-demo}"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
BUCKET="tripwire-artifacts-${ACCOUNT}-${AWS_REGION}"

aws cloudformation delete-stack --stack-name "$STACK"
aws cloudformation wait stack-delete-complete --stack-name "$STACK"
aws s3 rm "s3://${BUCKET}" --recursive
aws s3api delete-bucket --bucket "$BUCKET"
echo "Deleted stack $STACK and bucket $BUCKET. (KMS keys enter a 7-30 day deletion window and stop billing once deleted.)"
