# Security design review — 2026-09-21

Reviewed baseline: `59db8366d41d4e5838089d87af8b99cd48594df3` (v0.1).
This is a source review and engineering remediation, not independent cryptanalysis
or a certification. The v0.2 composition requires independent review before a
security-sensitive rollout. No live AWS resources or QPU jobs were used in the
local review.

## Finding: the proposed quantum work factor does not exist

The circuit is H applied independently to eight qubits, then computational-basis
measurement. Its ideal output is eight independent fair bits. A classical
machine can sample the same ideal distribution with eight random bits; no
exponentially large state-vector simulation is necessary. The circuit does not
use the password-derived seed. This is a randomness source, not a password-bound
hard computation, verifiable delay function, or post-quantum construction.

The baseline effectively computes:

```
u = SHA256(SHA512(password || salt || pepper))
q = backend(u)
h = Argon2id(password, salt || q)
```

For the local backend, `q = SHA512(u)[:10]`. This is deterministic classical
hashing. For Braket, `q` is fresh randomness independent of `u`. For Lambda,
`q` comes from Redis keyed only by SHA256(salt), or from Braket on a cache miss.
Consequently the cloud digest is independent of the pepper. KMS decrypting a
pepper gives no protection when its contribution is discarded.

If q is public or copied from Redis, an attacker can evaluate every guess locally
without Braket. If q is missing, the legitimate verifier cannot reproduce the
hash either. If q is instead kept in a durable secret store, protection comes
from control of that store, not the quantum origin of q. A service fee is not an
intrinsic computational lower bound, and clients are not forced to repeat a
particular implementation's network calls.

The baseline warning that protection disappears only after large fault-tolerant
quantum computers arrive is therefore misleading: this weakness already exists
for classical attackers.

## Baseline findings and disposition

| Severity | Finding | Consequence | v0.2 treatment |
| --- | --- | --- | --- |
| Critical | Braket ignores seed; fixed backend ignores pepper | Cloud hashes lack intended pepper protection | HMAC authenticates the actual Argon2 result |
| Critical | Only copy of quantum bytes expires after 120s | Correct password fails after expiry; simultaneous misses can disagree | Complete persistent record; no cache dependency |
| High | Claimed per-guess quantum call is avoidable | Security model overstates protection | Claims removed; explicit DB-only threat model |
| High | Unauthenticated caller can select QPU/shot count | Potential cloud-cost abuse if handler exposed | Private service accepts only bounded hash/verify payloads |
| High | Library does not bound Argon2 resources | Allocation/CPU denial of service | Strict parser and server-side verification ceilings |
| High | Import requires QS_PEPPER even for KMS path/help | Lambda initialization and ordinary tooling can fail | Legacy secret resolved only when used |
| High | Bare digest omits backend and cost parameters | Verification/migration depends on undocumented external state | Canonical, versioned, authenticated record |
| High | CDK omits promised KMS/cache and allocates default 128 MiB | Infrastructure cannot run documented 256 MiB hashing path | New private Lambda/KMS stack with resource tests |
| Medium | Count histogram used instead of shot sequence | Repeated outcomes regrouped; sequence entropy not preserved | Validate and preserve per-shot measurement rows |
| Medium | CLI password in argv; raw errors; silent cloud cost-flag mismatch | Exposure and misleading interface | Prompt/stdin, explicit format, fixed service policy |
| Medium | Packaging copies module without distribution metadata | Installed-version fallback can fail in artifact | Install built wheel into isolated Lambda artifact |
| Medium | CI ignores synthesis failure | Broken deployment can appear green | Synthesis and artifact smoke test required |
| Medium | Docs promise nonexistent Terraform, recovery, rotation | Operators may destroy verification state | Replace with implemented procedures |

The original 65 tests passed. Most verified happy paths or a cached deterministic
mock; they did not demonstrate the desired security properties. Regression tests
now explicitly reproduce both original cloud defects, test fresh-process
verification and key rotation, reject malformed/over-budget records before
expensive work, and check the real boto3 request shape with Stubber.

## Replacement: an enforceable service boundary

v0.2 uses Argon2id followed by HMAC-SHA256 over the versioned header and Argon2
result. Only the tag and public header are stored. Local deployments keep a
32-byte HMAC key outside the password DB. The AWS service instead uses a
non-exportable KMS HMAC_256 key with GenerateMac. There is no key decryption into
Lambda and no Braket dependency in the login path.

For a database-only thief without the HMAC key or access to a MAC/verification
oracle, stored tags do not permit the normal local password-guess comparison.
If the thief also obtains a local pepper, or can invoke the KMS key/service,
that additional boundary no longer holds. Argon2 still imposes work. Access
controls, account rate limits, monitoring and separation of duties remain
necessary. Lambda concurrency is an availability/cost cap, not an account
lockout policy. KMS does not independently enforce per-user password limits.

The application must protect DB writes and bind stored rows to users. The record
does not encode an account ID; a DB writer could swap records between accounts.
This library is not an authentication system, session manager, or encryption API.
Do not persist or log the pre-HMAC Argon2 result alongside the protected record;
it would provide an unpeppered guessing target.

Quantum measurements can optionally supplement OS randomness during enrollment.
They are mixed into the public salt. No claim is made that this strengthens an
already secure OS RNG, that hardware measurements are unbiased, or that a cloud
provider proves their origin. Verification needs neither the device nor its
original output. This is a retained experimental feature, not the security case.

## What a genuine quantum speedbump would need

A research continuation needs a precise attacker model, a password-bound
function, reproducible verification, explicit treatment of public/secret state,
and evidence that the best classical alternative has the desired cost. It must
address parallel guessing, preprocessing, amortization across users, noisy
hardware, stable outputs, and service compromise. Benchmarking Braket latency
against local hashing would not establish such a lower bound. That is a separate
research project; this change does not claim to solve it.

## Deployment evidence still required

Local tests and synthesized templates are not a live cloud acceptance test.
Before rollout: run the real KMS/least-privilege integration checks, measure p95
and p99 latency at the chosen Lambda memory/concurrency, connect alarms to an
owned incident channel, test key retention and rollback, and obtain an
independent review of the protocol and integration. See `docs/runbook.md`.

## Primary references

- [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html): Argon2 inputs and profiles.
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html): pepper separation and post-hash HMAC.
- [AWS GenerateMac](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateMac.html): supported HMAC keys and API contract.
- [AWS Braket result types](https://docs.aws.amazon.com/braket/latest/developerguide/braket-result-types.html): measurements and simulator/result semantics.
