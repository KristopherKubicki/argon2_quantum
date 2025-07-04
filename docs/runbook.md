# QS KDF Runbook

## Cache Keys

Redis keys derive from `sha256(salt)` with a 120s TTL. Cached quantum bytes
avoid repeated KMS calls. The cache window slightly reduces entropy but keeps
latency acceptable for interactive logins.

## Failure Modes

* **KMS Timeout**: Step Function enforces a 200 ms deadline and falls back to
  a deterministic slice when exceeded.
* **KMS Failure**: Lambda returns an error; monitoring via CloudWatch.
* **Redis Unavailable**: Lambda proceeds without cache and stores result when
possible.

## Two-Hash Migration

Passwords are hashed with the old method and the quantum-extended version in
parallel. After all users rotate their credentials, the quantum layer can be
removed without disrupting verification.
