"""Explicit verification-only migration for deterministic v0.1 local records."""

from .constants import _load_pepper
from .core import LocalBackend, verify_password
from .records import password_bytes


def verify_local(
    password: str,
    salt_hex: str,
    digest_hex: str,
    *,
    time_cost: int = 3,
    memory_cost: int = 262_144,
    parallelism: int = 4,
) -> bool:
    password_bytes(password)
    if not isinstance(salt_hex, str) or len(salt_hex) > 64:
        raise ValueError("invalid legacy salt")
    if not isinstance(digest_hex, str) or len(digest_hex) != 64:
        raise ValueError("invalid legacy digest")
    for value, low, high in (
        (time_cost, 1, 10),
        (memory_cost, 32, 1_048_576),
        (parallelism, 1, 8),
    ):
        if type(value) is not int or not low <= value <= high:
            raise ValueError("invalid legacy Argon2 parameters")
    if memory_cost < 8 * parallelism:
        raise ValueError("legacy memory cost must be at least 8 * parallelism")
    salt, digest = bytes.fromhex(salt_hex), bytes.fromhex(digest_hex)
    if len(digest) != 32:
        raise ValueError("invalid legacy digest")
    return verify_password(
        password,
        salt,
        digest,
        backend=LocalBackend(),
        pepper=_load_pepper(),
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
    )
