# Getting Started

This guide walks through hashing and verifying a password with the simulated
quantum stretch. A Python 3.10+ environment is required.

## Installation

```bash
pip install .
```

## Hash a Password

```bash
python -m qs_kdf hash "hunter2" --salt 0011223344556677
```

Pass `--cloud` to route the request through the Lambda handler. In this demo it
returns a fixed value but shows how the API would be used in production.

## Verify a Password

```bash
python -m qs_kdf verify "hunter2" --salt 0011223344556677 --digest <hex>
```

`verify` exits with the digest result printed to stdout (`OK` or `NOPE`).

## Deploying the Lambda

The `infra` directory contains an AWS CDK stack that provisions the Lambda,
KMS key and Redis cache. Deploy with:

```bash
cd infra
cdk deploy
```

The placeholder quantum step calls AWS Braket. You must provide appropriate
credentials and network access for the deployment to succeed.
