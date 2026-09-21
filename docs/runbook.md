# Release and operations runbook

## Local release gates

- Full tests including negative-input, rotation, concurrency, and legacy regressions.
- Ruff lint/format, Bandit, and required pre-commit checks.
- Hash-locked AWS runtime passes dependency audit.
- Wheel/sdist build; fresh artifact works outside the source tree without secrets
  at import time; Argon2 native extension loads.
- Actual packaged Lambda asset synthesizes; template tests assert retained keys,
  private access, constrained IAM permissions, and capacity settings.

## Live acceptance gates

These checks require the target AWS account and application integration. Passing
local tests is not evidence that these gates have passed.

1. Invoke real KMS-backed enrollment and verification with an authorized test
   application. Test wrong passwords, fresh Lambda instances, and cold starts.
2. Confirm an unauthorized principal cannot invoke the function or use its KMS
   keys. Inspect deployed IAM/key policies, not just the CDK source.
3. Load-test realistic password traffic. Record p50/p95/p99 latency, cold starts,
   memory usage, throttles and cost. Configure per-account and per-source rate
   limits at the application. Reserved concurrency alone is insufficient.
4. Revoke key access in staging and verify the application returns an availability
   error without fallback or password reset. Restore access and confirm records
   still verify.
5. Rotate to a second retained key. Verify records for both generations, test
   on-login replacement, then restore a backup needing the old key.
6. Connect alarms to an owned incident destination and test delivery. Audit logs
   and traces for accidental passwords or raw hash intermediates; disable SDK
   debug logging in production.
7. Review record-to-account integrity, generic login errors, account recovery,
   MFA/session handling, and atomic migration in the consuming application.
8. Obtain independent security review of the record protocol and integration.

## Failure handling

- `ProviderUnavailable`: transient protected-key failure, not a bad password.
  Return an appropriate service-unavailable response. Do not retry without bounds
  or fall back to a local/unpeppered verifier. KMS client retries are bounded.
- `UnknownKey`: keyring, rotation, or restore problem. Preserve the record and
  investigate configuration. Do not silently select the current key.
- `InvalidRecord`: corruption, unsupported format, or resource-policy mismatch.
  Preserve evidence without logging credentials; fail closed.
- Throttles: inspect abuse/rate limits and capacity before raising concurrency.
- Optional Braket failure: enrollment command fails; existing record verification
  is unaffected. A timed-out job may still incur AWS charges; inspect its status
  in Braket before retrying.

## Recovery and rotation

There is no Redis cache to flush. The database record is all public verification
state; its corresponding protected key must remain available. Follow the add-key,
verify-old, rehash-on-login procedure in `deployment.md`. Count remaining records
per key ID before retirement and include backup retention in the decision.
Deleting a needed key or losing a local pepper prevents verification and usually
requires account recovery. Never remove old keys simply because 24 hours elapsed.

Roll back only to builds that understand all formats already written. Do not
mutate stored costs/key IDs to force compatibility. A compromised local pepper
requires new keys plus re-enrollment; a stolen database and stolen pepper can
still be attacked after rotation. KMS IAM compromise requires revoking access,
investigating oracle use, and an incident-specific credential recovery decision.

## Reproducible local baseline

Run `python scripts/benchmark.py --samples 30` for a synthetic local HMAC
verification baseline. `docs/security/local-benchmark.json` records the review
machine's measurements. It excludes KMS, network latency, Lambda cold starts,
and concurrent traffic, so it must not be treated as a production latency SLO.
