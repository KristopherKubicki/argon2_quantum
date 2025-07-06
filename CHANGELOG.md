# Changelog

- [experimental] Quantum-Stretch KDF enabled for new logins; legacy hashes auto-upgrade on first successful auth.
- `QS_PEPPER` environment variable is now mandatory; the library raises a
  `RuntimeError` if it is unset.
