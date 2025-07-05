"""Constant values used across the quantum stretch KDF."""

PEPPER = b"fixedPepper32B012345678901234567"  # 32 bytes used for demo

# Maximum lengths enforced by the CLI and Lambda handler
MAX_PASSWORD_BYTES = 64
MAX_SALT_BYTES = 32
