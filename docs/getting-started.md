# Getting Started

This guide walks through hashing and verifying a password with the simulated
quantum stretch. A Python 3.10+ environment is required.

## Prerequisites

- An AWS account with permissions to deploy resources.
- [AWS CLI](https://docs.aws.amazon.com/cli/) installed and configured with
  IAM credentials.

## Installation

```bash
pip install .
# argon2-cffi is installed as a required dependency
```

Install the development dependencies when running linting or tests:

```bash
pip install -r requirements-dev.txt
```

## Hash a Password

```bash
python -m qs_kdf hash "hunter2" --salt 0011223344556677
```

By default the command uses a local simulator backend and requires no AWS
connectivity. Pass `--cloud` to route the request through the Lambda handler.
In this demo it returns a fixed value but shows how the API would be used in
production.

The repository ships with a static 32-byte pepper used for these examples.
Replace it with your own secret when deploying.

## Verify a Password

```bash
python -m qs_kdf verify "hunter2" --salt 0011223344556677 --digest <hex>
```

`verify` exits with the digest result printed to stdout (`OK` or `NOPE`).

## Deploying the Lambda

The stack defined in [`infra/qs_kdf_stack.py`](../infra/qs_kdf_stack.py)
provisions the Lambda, KMS key and Redis cache. Deploy with:

```bash
cd infra && cdk deploy
```

Alternatively run:

```bash
terraform -chdir=terraform apply
```

The random byte is fetched from AWS Braket by running a tiny circuit. Ensure
your credentials permit Braket execution. See the
[Braket documentation](https://docs.aws.amazon.com/braket/)
for further details.
