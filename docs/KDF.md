# Quantum Stretch KDF

## Threat Model

| Actor         | Capability                      | Mitigation                   |
|---------------|---------------------------------|------------------------------|
| Offline brute | Tries to guess passwords        | Quantum stretch + Argon2     |
| Insider       | Reads DB and cache              | KMS protected pepper         |
| Network       | Snoops traffic                  | TLS enforced by API Gateway  |

## Flow Diagram

```
client -> API Gateway -> Lambda qs_kdf -> Redis/KMS -> Braket -> Argon2
```

## API Example

```bash
curl -X POST /auth/qs-login -d '{"password":"pw","salt":"01"}'
```

## Rollback

1. Disable Braket call in Lambda.
2. Keep Argon2 verification with stored digest.
3. Re-enable classical path only.
