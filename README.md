# Argon2 Quantum

[![CI](https://github.com/KristopherKubicki/argon2_quantum/actions/workflows/ci.yml/badge.svg)](https://github.com/KristopherKubicki/argon2_quantum/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/KristopherKubicki/argon2_quantum/graph/badge.svg?token=JuPPmkMFxR)](https://codecov.io/gh/KristopherKubicki/argon2_quantum)

**Quantum-enhanced Argon2 with a dash of real qubits.** The library fetches ten bytes of entropy from AWS Braket and folds them into the salt before running a classic Argon2 hash. The approach increases the cost of large-scale offline attacks, though it is *not* a post‑quantum scheme.

## Table of Contents
- [Background](#background)
- [Quick Start](#quick-start)
- [Infrastructure](#infrastructure)
- [Development](#development)
- [License](#license)

## Background
This project demonstrates a minimal "quantum stretch". A tiny circuit runs on managed quantum hardware or the simulator and returns ten truly random bytes. These bytes are appended to your chosen salt and fed into a normal Argon2 hashing step. The extra call to Braket raises the attacker's cost because each password guess must repeat the service call.

> **Security Notice**
> The quantum stretch slows classical brute force attempts but offers no resistance once large fault‑tolerant quantum computers exist.

## Quick Start
### Installation
```bash
pip install .
python -m qs_kdf hash mypassword --salt deadbeefcafebabe

# or let the CLI pick a salt for you
python -m qs_kdf hash mypassword
```

### Hash a password
```bash
python -m qs_kdf hash "mypassword" --salt deadbeefcafebabe
```

When no salt is provided the CLI prints the generated salt and digest separated
by a space. The salt must be saved for verification.

```bash
$ python -m qs_kdf hash mypassword
0123456789abcdef0123456789abcdef deadbeef...
```

Running without `--cloud` keeps all computation local using the built-in
simulator backend.

Set ``QS_WARMUP=1`` or call ``qs_kdf.warm_up()`` to preload Argon2 memory
for consistent benchmarking.

### QS_PEPPER

The pepper is loaded at runtime using ``qs_kdf.constants.get_pepper()``. Set
``QS_PEPPER`` to a 32-byte secret to override the shipped default. The CLI
requires this variable for local hashing. See
[docs/getting-started.md](docs/getting-started.md) for details.

The ``BraketBackend`` defaults to the IonQ QPU but accepts a ``device_arn``
parameter if you wish to target a different device.

The stack in [`infra/qs_kdf_stack.py`](infra/qs_kdf_stack.py) can be deployed
with a single command:

```bash
cd infra && cdk deploy
```

Verify:

```bash
python -m qs_kdf verify "mypassword" --salt deadbeefcafebabe --digest <hex>
```

Running without `--cloud` keeps everything local using the built-in simulator. For a deeper walkthrough see [docs/getting-started.md](docs/getting-started.md).

## Infrastructure
The stack in [`infra/qs_kdf_stack.py`](infra/qs_kdf_stack.py) deploys the Lambda function, KMS key and supporting resources. Validate locally:
```bash
cd infra
cdk synth
```
Deploy with `cdk deploy` or use the included Terraform module:
```bash
terraform -chdir=terraform apply
```
More background is available in the documents under [`docs/`](docs/).
See [docs/lambda-build.md](docs/lambda-build.md) for instructions on
packaging the Lambda function.
See [docs/deployment.md](docs/deployment.md) for AWS setup and
deployment steps.

## Development
Use Python 3.10 or newer. Install the hooks once:
```bash
pre-commit install
```
Run the hooks and tests before committing:
```bash
pre-commit run --files <files>
pip install -r requirements.txt -r requirements-dev.txt
pytest
```
Missing packages such as `argon2-cffi` will cause test failures.
Extra checks such as `mypy` or `bandit` are optional but recommended.

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
