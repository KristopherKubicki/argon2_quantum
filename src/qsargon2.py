"""Quantum stretch and Argon2 wrapper."""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Optional

PEPPER = b"fixedPepper32B012345678901234567"  # 32 bytes used for demo


def _reverse_bits(value: int, bit_width: int) -> int:
    """Reverse bits of ``value`` given ``bit_width``."""
    return int(f"{value:0{bit_width}b}"[::-1], 2)


def qstretch(password: str, salt: bytes, pepper: bytes = PEPPER) -> bytes:
    """Return 256-bit stretched digest.

    The function is deterministic and reversible in spirit but implemented
    classically for this demo.
    """
    data = password.encode() + salt + pepper
    digest = hashlib.sha512(data).digest()  # 64 bytes
    result = bytearray()
    for i in range(0, len(digest), 8):
        chunk = digest[i : i + 8]
        val = int.from_bytes(chunk, "big")
        rev = _reverse_bits(val, 64)
        result.extend(rev.to_bytes(8, "big"))
    return bytes(result[:32])


def hash_password(
    password: str,
    salt: Optional[bytes] = None,
    pepper: bytes = PEPPER,
) -> bytes:
    """Hash ``password`` using qstretch + scrypt.

    Args:
        password: Raw password string.
        salt: Optional salt. Random if ``None``.
        pepper: Server-side pepper bytes.

    Returns:
        32-byte digest.
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    pre = qstretch(password, salt, pepper)
    digest = hashlib.scrypt(pre, salt=salt, n=2**14, r=8, p=1, dklen=32)
    return digest


def main() -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Demo Argon2 Quantum wrapper")
    parser.add_argument("password", help="Password to hash")
    parser.add_argument("--salt", help="Hex salt", default=None)
    args = parser.parse_args()
    salt = bytes.fromhex(args.salt) if args.salt else secrets.token_bytes(16)
    digest = hash_password(args.password, salt)
    print(base64.b64encode(digest).decode())


if __name__ == "__main__":
    main()
