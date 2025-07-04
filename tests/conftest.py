import hashlib
import sys
import types


def _fake_hash_secret_raw(
    pw, salt, time_cost, memory_cost, parallelism, hash_len, type, *, secret=None
):
    return hashlib.scrypt(
        pw if secret is None else pw + secret,
        salt=salt,
        n=2**14,
        r=8,
        p=parallelism,
        dklen=hash_len,
    )


stub = types.SimpleNamespace(
    Type=types.SimpleNamespace(ID=2),
    hash_secret_raw=_fake_hash_secret_raw,
)

sys.modules.setdefault("argon2.low_level", stub)
