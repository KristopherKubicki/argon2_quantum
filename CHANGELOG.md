# Changelog

## 0.2.0 — release candidate

- Add versioned Argon2id/HMAC records and strict resource-bounded verification.
- Add local keyrings and non-exportable KMS HMAC provider with explicit rotation.
- Replace expiring-cache cloud hashing with a private hash/verify Lambda API.
- Prompt for passwords or accept bounded stdin; migrate legacy local records explicitly.
- Remove secret requirements at import; package wheel metadata in Lambda artifact.
- Correct quantum security claims and preserve measurement shot order.
- Replace incomplete infrastructure with retained KMS keys, bounded Lambda capacity,
  logs and alarms; require synthesis/artifact checks in CI.
- Keep legacy byte-digest APIs for compatibility only. Old cloud random bytes that
  expired cannot be reconstructed. This is a breaking CLI and cloud API release.

Independent security review and live AWS acceptance remain required before release.
