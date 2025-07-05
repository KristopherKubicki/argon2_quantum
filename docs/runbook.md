# QS KDF Runbook

## Cache Keys

Redis keys derive from `sha256(salt)` with a 120s TTL. Cached quantum bytes
avoid repeated Braket calls. The cache window slightly reduces entropy but keeps
latency acceptable for interactive logins.

Recent versions request all ten quantum shots in a single `device.run` call.
This reduces network latency and simplifies error handling compared to the
previous per-shot loop.

## Failure Modes

* **Braket Timeout**: Step Function enforces a 200 ms deadline. Invocations
  exceeding this limit return an error.
* **Braket Failure**: Lambda returns an error; monitoring via CloudWatch.
* **Redis Unavailable**: Lambda proceeds without cache and stores result when
possible.

## Two-Hash Migration

Passwords are hashed with the old method and the quantum-extended version in
parallel. After all users rotate their credentials, the quantum layer can be
removed without disrupting verification.

## Operational Tasks

* **Cache Flush**: run `redis-cli FLUSHALL` to clear stored quantum bytes when
  corruption is suspected or after a major upgrade.
* **Pepper Rotation**: update the `QS_PEPPER` secret and redeploy the Lambda
  function. Old peppers remain valid for 24 hours to avoid lockouts.
* **Redeploy Steps**: build the container, push to ECR and run `make deploy`
  from the CI runner. Ensure the Step Function points at the new image tag.
* **Monitoring Tips**: watch CloudWatch for Braket errors, Redis latency and
  container restarts. Alert on sustained spikes or missing metrics.
