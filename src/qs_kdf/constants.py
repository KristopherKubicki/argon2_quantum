"""Constant values used across the quantum stretch KDF."""

import os



def _load_pepper() -> bytes:
    """Return 32-byte pepper from ``QS_PEPPER``.

    Raises:
        RuntimeError: When ``QS_PEPPER`` is unset or not 32 bytes.

    Returns:
        bytes: Pepper value.
    """

    env = os.getenv("QS_PEPPER")
    if env is None:
        raise RuntimeError("QS_PEPPER environment variable required")
    value = env.encode()
    if len(value) != 32:
        raise RuntimeError("QS_PEPPER must be 32 bytes")
    return value


PEPPER = _load_pepper()

# Maximum lengths enforced by the CLI and Lambda handler
MAX_PASSWORD_BYTES = 64
MAX_SALT_BYTES = 32

# Boundaries for Argon2 parameters
MIN_TIME_COST = 1
MAX_TIME_COST = 10

MIN_MEMORY_COST = 32
MAX_MEMORY_COST = 1024 * 1024

MIN_PARALLELISM = 1
MAX_PARALLELISM = 8
