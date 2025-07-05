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

### Cloud mode

Running with `--cloud` invokes the deployed Lambda. Set the following
environment variables so the CLI can locate the key, pepper and cache:

```bash
export KMS_KEY_ID=<kms-key-id>
export PEPPER_CIPHERTEXT=<base64-ciphertext>
export REDIS_HOST=<redis-endpoint>
# Optional when not using the default port
export REDIS_PORT=6379
```

`cdk deploy` prints these values after provisioning. Export them before
executing the command.

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

The random bytes are fetched from AWS Braket by running a tiny circuit. Ensure
your credentials permit Braket execution. See the
[Braket documentation](https://docs.aws.amazon.com/braket/)
for further details.
