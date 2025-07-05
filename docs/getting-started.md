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

### Docker

Build the container image from the project root:

```bash
docker build -t qs_kdf .
```

Run the CLI by passing arguments to `docker run`:

```bash
docker run --rm qs_kdf hash "hunter2" --salt 0011223344556677
```

The image installs the package and exposes the ``qs_kdf`` command as the
entrypoint. Additional flags such as ``--cloud`` are forwarded unchanged.

## Hash a Password

```bash
python -m qs_kdf hash "hunter2" --salt 0011223344556677
```

You can omit `--salt` to generate a random 16-byte value. The salt is printed
alongside the digest:

```bash
python -m qs_kdf hash "hunter2"
0123456789abcdef0123456789abcdef deadbeef...
```

By default the command uses a local simulator backend and requires no AWS
connectivity. Pass `--cloud` to route the request through the Lambda handler.
In this demo it returns a fixed value but shows how the API would be used in
production.

The repository ships with a static 32-byte pepper used for these examples.
Set ``QS_PEPPER`` to override it when running locally and replace it with your
own secret when deploying.

Passwords longer than 64 bytes or salts over 32 bytes are rejected by both
the CLI and Lambda handler to keep memory usage predictable.

### Local simulation

The CLI defaults to the ``LocalBackend`` which slices a SHA‑512 digest of the
stretched password to produce ten deterministic bytes. This allows repeatable
hashing and verification without any AWS credentials. Use this mode for local
tests or CI runs. Set ``QS_PEPPER`` to your 32-byte secret so the hash matches
production behavior.

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

First generate a digest then check it against the original password:

```bash
digest=$(python -m qs_kdf hash "hunter2" --salt 0011223344556677)
python -m qs_kdf verify "hunter2" --salt 0011223344556677 --digest "$digest"
```

``OK`` means the password matches while ``NOPE`` indicates a mismatch.

If the salt was auto-generated, pass the printed values back to `verify`:

```bash
python -m qs_kdf verify "hunter2" --salt <printed-salt> --digest <printed-digest>
```

`verify` exits with the digest result printed to stdout (`OK` or `NOPE`).

## Building the Lambda Artifact

Deployments expect a zipped package under `build/lambda.zip`. Create it with:

```bash
./scripts/package_lambda.sh
```

The script installs runtime requirements into `build/lambda`, copies the
source code and zips the directory for the CDK stack.

## Deploying the Lambda

Follow these steps to provision the cloud resources:

1. Build the Lambda package if not already present:

   ```bash
   ./scripts/package_lambda.sh
   ```

2. Deploy the CDK stack:

   ```bash
   cd infra && cdk deploy
   ```

   The command prints ``KMS_KEY_ID``, ``PEPPER_CIPHERTEXT`` and
   ``REDIS_HOST``. Export them for the CLI to locate the key, pepper and cache:

   ```bash
   export KMS_KEY_ID=<kms-key-id>
   export PEPPER_CIPHERTEXT=<base64-ciphertext>
   export REDIS_HOST=<redis-endpoint>
   export REDIS_PORT=6379  # optional when using the default port
   export REDIS_TLS=1      # disable with 0/false/no
   export REDIS_CERT_REQS=required  # none|optional|required
   ```

``REDIS_TLS`` defaults to ``1``. Disabling TLS is strongly discouraged.
``REDIS_CERT_REQS`` defaults to ``required``. Setting it to ``none`` skips
certificate verification and is unsafe outside tests. ``optional`` allows
failures while keeping TLS enabled.

The random bytes are fetched from AWS Braket by running a tiny circuit. Ensure
your credentials permit Braket execution. See the
[Braket documentation](https://docs.aws.amazon.com/braket/)
for further details. ``BraketBackend`` uses the IonQ device by default but you
may pass ``device_arn`` to select a different ARN.
