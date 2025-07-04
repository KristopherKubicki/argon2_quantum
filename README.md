# Argon2 Quantum

This project demonstrates a quantum inspired pre-hash using a random byte
retrieved from AWS Braket followed by a classic memory-hard KDF. The quantum
step executes a simple circuit on the managed simulator.

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

Install dependencies and run the CLI to hash a password with a hex salt:

```bash
pip install .
python -m qs_kdf hash mypassword --salt deadbeefcafebabe
```

The output digest can later be verified with the `verify` subcommand:

```bash
python -m qs_kdf verify mypassword --salt deadbeefcafebabe --digest <hex>
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

## Dependency Management

All Python packages are pinned in `requirements.txt` and `pyproject.toml`.
When updating a dependency:

1. Review the package's changelog and security notes.
2. Modify the version in both files to match.
3. Run `ruff`, `bandit` and the full test suite before submitting a PR.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for
details.
