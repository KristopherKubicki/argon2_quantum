# Quantum Stretch KDF

## Threat Model

| Actor         | Capability               | Mitigation                     |
|---------------|-------------------------|--------------------------------|
| Offline brute | Tries to guess passwords| Quantum stretch + Argon2       |
| Insider       | Reads DB and cache      | KMS protected pepper           |
| Network       | Snoops traffic          | TLS enforced by API Gateway    |

The quantum byte is fetched from AWS Braket in production or generated locally
during development. This makes brute-force attempts expensive because each
password guess must reproduce the extra step.

## Flow Diagram

```
client -> API Gateway -> Lambda qs_kdf -> Redis/Braket -> Braket -> Argon2
```

Redis caches the quantum byte for a short period to reduce latency. The Lambda
function can operate without the cache but will incur extra calls to Braket.

## API Example

```bash
curl -X POST /auth/qs-login -d '{"password":"pw","salt":"01"}'
```

## Rollback

1. Disable the Braket call in Lambda.
2. Keep Argon2 verification with the stored digest.
3. Re-enable the classical path only.
