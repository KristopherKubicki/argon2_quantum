# Migrating v0.1 records

v0.2 records deliberately have a new prefix and construction. Do not reinterpret
a bare v0.1 digest as a v0.2 record or replace the existing bytes in place without
first verifying the password. Back up existing data before changing an integration.

## Deterministic local backend

You need the original salt, digest, QS_PEPPER, and Argon2 parameters. With those
values present, the exact original computation remains available through
`qs_kdf.legacy.verify_local`. After successful verification, enroll a v0.2 record
and atomically replace the old row. The CLI offers:

```bash
# QS_PEPPER is the original v0.1 32-byte UTF-8 secret.
# QS_PEPPER_HEX or --keyring supplies the new v0.2 key separately.
qs_kdf migrate-legacy --salt '<old-salt-hex>' --digest '<old-digest-hex>'
```

Pass the old `--time-cost`, `--memory-cost` (KiB), and `--parallelism` if they
were nondefault. The default legacy costs remain 3/262144/4. Migration's explicit
legacy resource bounds are wider than the v0.2 login service; do not expose this
CLI as an unauthenticated service. Wrong passwords do not produce a replacement.

For an online migration, tag database rows with their actual old scheme. Dispatch
to the explicit legacy verifier only for those rows, never because a v0.2 check
failed. Remove the old verifier and old pepper when migration and backup-retention
requirements are complete. Do not retain an unpeppered fallback digest alongside
the stronger record.

## Braket/cloud backend

The original cloud path did not persist the quantum salt extension beyond a
120-second Redis entry. If those exact bytes are gone, the old hash cannot be
reproduced from password, original salt, and pepper. A new QPU call will not
recover them. Arrange account recovery/password reset; no code change can restore
missing random state.

If the exact original extension was durably saved, an application-specific
migration can verify the old Argon2 result with `salt || saved_extension`, then
enroll a v0.2 record on successful login. The generic migration CLI deliberately
does not guess which backend created a digest.

The original pepper was ineffective in the cloud path. Rotating it does not fix
existing cloud digests. Do not claim that legacy cloud records acquire v0.2's
protection without re-enrollment.

## Rollback

Deploy a reader that understands both explicitly tagged formats before writing
v0.2 records. A v0.1-only application cannot verify v0.2 records. Roll back to a
v0.2-capable build and keep the keyring intact. Never drop KMS keys or flush old
state as a rollback strategy.
