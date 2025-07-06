# Quantum Stretch KDF

## Threat Model

| Actor         | Capability               | Mitigation                     |
|---------------|-------------------------|--------------------------------|
| Offline brute      | Tries to guess passwords     | Quantum stretch + Argon2        |
| Insider            | Reads DB and cache           | KMS protected pepper            |
| Network            | Snoops traffic               | TLS enforced by API Gateway     |
| Phishing attacker  | Tricks users to reveal creds | MFA and user training           |
| Compromised CI/CD  | Injects backdoor via builds  | Signed artifacts, reviews       |
| Cloud insider      | Access to infrastructure     | Encryption, role separation     |
| Quantum adversary  | Large-scale QPU              | Monitoring, limited benefit     |

The quantum bytes are fetched from AWS Braket in production or generated locally
during development. The small circuit used to obtain them is outlined in
[quantum-circuit.md](quantum-circuit.md). This extra step makes brute-force
attempts expensive because each password guess must reproduce the service call.

## Flow Diagram

```
client -> API Gateway -> Lambda qs_kdf -> Redis/Braket -> Braket -> Argon2
```

Redis caches the quantum bytes for a short period to reduce latency. The Lambda
function can operate without the cache but will incur extra calls to Braket.

## Hashing Workflow

1. The client submits the password and a user-specific salt.
2. The Lambda handler decrypts the pepper using AWS KMS.
3. It checks Redis for quantum bytes keyed by the salt.
4. On a miss the Braket backend generates fresh bytes and stores them in the cache.
5. These bytes extend the provided salt before hashing.
6. Argon2id hashes the password concatenated with the pepper using the new salt.
7. The resulting digest is returned to the client or stored for verification.

## API Example

```bash
curl -X POST /auth/qs-login -d '{"password":"pw","salt":"01"}'
```

## Rollback

1. Disable the Braket call in Lambda.
2. Keep Argon2 verification with the stored digest.
3. Re-enable the classical path only.

## Not Post-Quantum Secure

The quantum stretch only adds a minor delay to each password guess by
requiring the attacker to repeat the AWS Braket call. A sufficiently
powerful quantum computer can execute the same circuit and still apply
Grover's search to the password space. The scheme therefore does not
provide post-quantum security, merely a short-term increase in cost.
