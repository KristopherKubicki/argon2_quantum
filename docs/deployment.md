# Deployment Guide

This document explains how to provision the cloud resources and set up the
environment for both Lambda and local runs.

## AWS Prerequisites

- An AWS account with permissions to create IAM roles, Lambda functions,
  KMS keys and Step Functions.
- AWS CLI configured with credentials able to deploy using CDK or Terraform.
- Choose a region supported by AWS Braket (for example `us-east-1`).

## Deploying the CDK Stack

1. Build the Lambda package if not already present:

   ```bash
   ./scripts/package_lambda.sh
   ```

2. Deploy the stack:

   ```bash
   cd infra && cdk deploy
   ```

   The command prints the values required to run the CLI in cloud mode.

## Deploying with Terraform

The repository also ships with a Terraform module mirroring the CDK stack.
Apply it as follows:

```bash
terraform -chdir=terraform apply
```

## Environment Variables

Export these variables so both the CLI and Lambda handler can locate the
required secrets and cache:

```bash
export KMS_KEY_ID=<kms-key-id>
export PEPPER_CIPHERTEXT=<base64-ciphertext>
export REDIS_HOST=<redis-endpoint>
export REDIS_PORT=6379  # optional when using the default
```

For local testing omit `--cloud` and these variables are ignored. Running in
cloud mode requires them to be present in the Lambda configuration or your
shell environment.
