# Argon2 Quantum

[![CI](https://github.com/KristopherKubicki/argon2_quantum/actions/workflows/ci.yml/badge.svg)](https://github.com/KristopherKubicki/argon2_quantum/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/KristopherKubicki/argon2_quantum/graph/badge.svg?token=JuPPmkMFxR)](https://codecov.io/gh/KristopherKubicki/argon2_quantum)

This project demonstrates a quantum inspired pre-hash using ten random bytes.
The bytes come from running a tiny qubit circuit via AWS Braket. By default the
circuit executes on real quantum hardware, though the managed simulator is also
available. The output then seeds a classic memory-hard KDF.

> **Security Notice**
> 
> The approach only raises the cost of classical offline attacks. It does
> **not** provide post-quantum security.

## ELI5

Imagine you want to lock your cookie jar with a secret code. This project adds
a tiny piece of random "sprinkle" from the cloud before scrambling the code
with Argon2. The sprinkle slows down classical attackers but offers no
resistance once quantum computers arrive.

## Getting Started

### Prerequisites

- An AWS account with permissions to create Lambda, KMS and Braket resources via CDK or Terraform.
- Configured IAM credentials using the [AWS CLI](https://docs.aws.amazon.com/cli/).

Install dependencies and run the CLI to hash a password with a hex salt.
`argon2-cffi` is required and will be installed automatically:

```bash
pip install .
python -m qs_kdf hash mypassword --salt deadbeefcafebabe

# or let the CLI pick a salt for you
python -m qs_kdf hash mypassword
```

The output digest can later be verified with the `verify` subcommand:

```bash
python -m qs_kdf verify mypassword --salt deadbeefcafebabe --digest <hex>
```

When no salt is provided the CLI prints the generated salt and digest separated
by a space. The salt must be saved for verification.

```bash
$ python -m qs_kdf hash mypassword
0123456789abcdef0123456789abcdef deadbeef...
```

Running without `--cloud` keeps all computation local using the built-in
simulator backend.

The stack in [`infra/qs_kdf_stack.py`](infra/qs_kdf_stack.py) can be deployed
with a single command:

```bash
cd infra && cdk deploy
```

or using Terraform:

```bash
terraform -chdir=terraform apply
```

For an overview of the approach and more deployment tips see the documents in
[`docs/`](docs/).

## Infrastructure

The AWS resources are defined with the CDK in [`infra/`](infra/). Validate the
stack locally with:

```bash
cd infra
cdk synth
```

Deploy the stack using `cdk deploy` when you're ready.

## Development

Use Python 3.10 or newer. Install the hooks once:

```bash
pre-commit install
```

Run the hooks on changed files and execute tests before committing:

```bash
pre-commit run --files <files>
pytest
```

Tools like `mypy` or `bandit` can optionally be run for extra checks.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for
details.
