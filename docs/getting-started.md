# Getting started

Install the base package with `python -m pip install .`. Only Argon2 is required
for local operation. AWS and QPU features use `.[aws]` and `.[quantum]` extras.
Import, `--help`, and `--version` do not need a secret or AWS credentials.

## Local keys

Generate a 32-byte secret once and store it securely. For a single key, provide
64 hex characters in `QS_PEPPER_HEX`; the key ID defaults to `local-1` and can be
set using `QS_CURRENT_KEY_ID`. Never put real secrets into source control.

For rotation, use a protected JSON keyring file:

```json
{"current":"k2","keys":{"k1":"<64 hex characters>","k2":"<64 hex characters>"}}
```

Replace the placeholders with independently generated secrets. Restrict file
access to the application user, and keep encrypted backups separately from the
password database. Use `qs_kdf hash --keyring /secure/keys.json` and
`qs_kdf verify --keyring /secure/keys.json --record '<complete-record>'`.
The CLI prompts without echo. `--password-stdin` consumes one line, removing only
its terminating newline; it does not trim other whitespace. The Python API
supports passwords with embedded newlines and NULs. Shell pipelines that place
literal passwords in history are not a safe secret-input mechanism.

Hash exits 0 on success. Verify exits 0 for a match and 1 for mismatch.
Invalid records/configuration exit 2; protected-key service outages exit 3.
Exceptions in the library distinguish these conditions as well.

## KMS keys

Use `--kms` with the allowlist configuration described in `deployment.md`.
AWS credentials must permit HMAC operations on the configured keys. This CLI
calls KMS locally; it is not a Lambda invocation client. Never provide
untrusted clients with this access. Ordinary applications invoke the private
Lambda through an IAM-authorized backend instead.

## Existing users

Do not overwrite old records or regenerate old salts. See `migration.md` for the
explicit local migration command and unrecoverable legacy cloud state.
