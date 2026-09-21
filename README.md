# Argon2 Quantum / Quantum Speedbump

Versioned Argon2id password records protected by a local pepper or a
non-exportable AWS KMS HMAC key. Optional quantum measurements can supplement
salt generation at enrollment; verification is independent of Braket and Redis.

**Status:** v0.2 is a breaking-format release candidate. The original quantum
work-factor claim was not supported by the circuit. The replacement's security
boundary is Argon2 plus protected-key access, not quantum computational hardness.
Read the [design review](docs/security/design-review.md) and
[release checklist](docs/runbook.md) before deploying. This is password hashing,
not reversible encryption or a post-quantum algorithm.

## Quantum Annoying Lab

Can a captured login force an attacker to solve different discrete logarithms
for different password guesses? The [research lab](research/README.md) explores
that question with a reproducible toy protocol, executable attacks, and an
[interactive results report](research/results/index.html) (download and open locally).
This is source-only research, excluded from the production wheel. It is not a
deployable cryptographic construction or a claim of measured quantum resistance.

## Quick start

Python 3.10+:

```bash
python -m pip install .
# Generate once and store securely, separately from the password database.
export QS_PEPPER_HEX="$(python -c 'import secrets; print(secrets.token_hex(32))')"
qs_kdf hash
# Save the entire printed record; verification prompts for the password.
qs_kdf verify --record '$qs$2$argon2id$...'
```

Use `--password-stdin` for automation. Passwords are not accepted as command-line
arguments. Do not generate a new pepper at every application start. Back up the
pepper securely: losing it prevents verification of its records.

```python
from qs_kdf import LocalPepper, PasswordHasher

# Obtain 32 random secret bytes from your secret manager.
hasher = PasswordHasher(LocalPepper({"k1": secret_key}), current_key_id="k1")
record = hasher.hash("a user-supplied passphrase")
# Save record in the user's row. No additional salt/cache state is needed.
valid = hasher.verify("a user-supplied passphrase", record)
if valid and hasher.needs_rehash(record):
    replacement = hasher.hash("a user-supplied passphrase")
    # Atomically replace the old record in your database.
```

## AWS service

Install `.[aws]` for the KMS provider. The [CDK deployment](docs/deployment.md)
creates a private Lambda, retained HMAC key, logs, and alarms. It requires IAM
invocation permissions and exposes no public HTTP endpoint. The application
handles user authorization, rate limits, and durable record storage.

```json
{"action":"hash","password":"a user-supplied passphrase"}
```

Returns `{"record":"$qs$2$..."}`. Verify using:

```json
{"action":"verify","password":"a user-supplied passphrase","record":"$qs$2$..."}
```

Returns `{"valid":true,"needs_rehash":false}`. Treat provider errors as service
unavailability. See [protocol details](docs/KDF.md) and [operations](docs/runbook.md).

## Optional quantum experiment

Install `.[quantum]` and supply an explicit Braket device ARN:

```bash
qs_kdf hash --quantum-device-arn '<device-arn>'
```

This requests a paid Braket task at enrollment and fails if the backend fails.
It is not part of the deployed login service. The normal verification command
uses the persisted record and requires no QPU. See [quantum circuit](docs/quantum-circuit.md).

## Migration and development

- [Getting started and keyrings](docs/getting-started.md)
- [v0.1 migration](docs/migration.md)
- [Lambda packaging](docs/lambda-build.md)

```bash
python -m pip install -e '.[dev]'
pre-commit install
pre-commit run --all-files
pytest --cov=qs_kdf --cov-report=term-missing --cov-fail-under=85
```

Runtime AWS dependencies are hash-locked in `requirements-lambda.txt`. CI checks
Python 3.10–3.14, tests the deployment artifact, audits the AWS runtime lock, and
requires infrastructure synthesis to succeed. Live AWS acceptance and external
security review remain release gates; local tests do not replace them.

MIT licensed. See [LICENSE](LICENSE).
