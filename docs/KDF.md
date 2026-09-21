# Password record format v2

The production API is `qs_kdf.PasswordHasher`. The old `hash_password`,
`verify_password`, `qstretch`, and `qsargon2` APIs retain v0.1 behavior only for
compatibility; they are not the recommended enrollment interface.

## Construction

1. Accept a nonempty UTF-8 password of at most 1024 bytes. No normalization,
   truncation, whitespace stripping, or hidden encoding conversion is applied.
2. Generate 32 bytes using `secrets.token_bytes`. Compute a 32-byte public salt:
   `SHA256(b"qs-kdf:salt:v2\0" || os_random_32 || supplemental_entropy)`.
   Supplemental entropy defaults to empty; it is limited to 4096 bytes. A
   quantum source never replaces the OS randomness.
3. Compute 32 bytes with Argon2id v19, using the password and salt.
4. Build the canonical ASCII header below and compute:
   `HMAC-SHA256(key, b"qs-kdf:password-record:v2\0" || header || b"\0" || argon2_result)`.
5. Store `header + "$" + base64_no_padding(tag)`. Do not store the raw Argon2
   result, password, or pepper. Salt and tag are each 32 bytes.

```
$qs$2$argon2id$v=19$m=65536,t=3,p=4$kid=k1$<salt-base64>$<tag-base64>
```

The header is everything before the final `$<tag-base64>`. Integers are decimal
without leading zeroes. Key IDs contain 1–32 ASCII letters, digits, `_` or `-`.
Base64 uses the standard alphabet without padding; noncanonical pad bits are
rejected. Records are at most 512 characters. Unknown versions/algorithms are
errors, never downgrade triggers. Key IDs select an application-owned allowlist,
not a client-supplied secret or cloud ARN.

## Parameters and bounds

The default is m=65536 KiB, t=3, p=4. This matches the memory-constrained profile
in [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html). Benchmark your actual
deployment before changing it.

Supported enrollment parameters: memory 19456–262144 KiB, passes 2–6, lanes 1–8.
`VerificationLimits` independently defaults to 65536/3/4 and rejects records
above these ceilings before allocating Argon2 memory. To enroll or verify larger
values, configure explicit limits within the supported bounds. The Lambda
service fixes both enrollment and verification to the default policy and accepts
no client-supplied cost overrides. Per-process concurrency must also be bounded.

Parsing and key lookup occur before expensive verification. A valid wrong
password returns False using `secrets.compare_digest` on fixed-size MACs.
Malformed records raise `InvalidRecord`; missing keys raise `UnknownKey`; KMS
failure raises `ProviderUnavailable`. Do not turn service failure into a success,
an unpeppered fallback, or a destructive password reset. Error paths do not have
identical timing; applications should avoid exposing account-existence details.

## Pepper providers and rotation

`LocalPepper({"k1": secret_bytes})` requires exactly 32 bytes per key. Keep these
keys in a secret manager or otherwise outside the password DB. `KmsMac` uses
HMAC_SHA_256 and immutable HMAC key ARNs. KMS performs the MAC operation without
exporting the key into the process. This follows the general post-hash pepper
approach described by [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

Add a new key under a new ID, retain the old mapping, and select the new current
ID. Verify with the record's old ID. After a successful login, check
`needs_rehash(record)` and replace the record with `hash(password)` using an
atomic DB update. Never rewrite just the key ID or parameters. Retain old keys
until no stored records or restorable backups require them. There is no automatic
24-hour grace period. Loss of a needed pepper requires password recovery/reset.

The record is a password verifier, not a reusable encryption key. Do not use its
tag as a session token or encryption key.

## Compatibility vector

For password `correct horse battery staple`, key bytes `00 01 ... 1f`, key ID
`k1`, OS randomness bytes `00 01 ... 1f`, empty supplemental entropy, and
m=19456/t=2/p=1, the complete record is:

```
$qs$2$argon2id$v=19$m=19456,t=2,p=1$kid=k1$z06c5H3Dw4+NUZNCbQL1PwTTGVzdbOIQUzo+lU3r4oE$C4Dbdvlas5s/jcMR6V2HFPtDenQdKf4sXCPYLiZPzjU
```

These are public test values, never production secrets. Tests independently
compose the underlying Argon2/HMAC operations and freeze this output to detect
unintentional protocol changes.
