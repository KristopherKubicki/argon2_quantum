"""Constant values used across the quantum stretch KDF."""

import os


_DEFAULT_PEPPER = b"fixedPepper32B012345678901234567"  # 32 bytes used for tests


def _load_pepper() -> bytes:
    env = os.getenv("QS_PEPPER")
    if env is None:
        return _DEFAULT_PEPPER
    value = env.encode()
    if len(value) != 32:
        raise RuntimeError("QS_PEPPER must be 32 bytes")
    return value


PEPPER = _load_pepper()

# Maximum lengths enforced by the CLI and Lambda handler
MAX_PASSWORD_BYTES = 64
MAX_SALT_BYTES = 32
