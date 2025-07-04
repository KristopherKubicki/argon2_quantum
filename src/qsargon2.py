"""Quantum stretch and Argon2 wrapper."""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Optional

from qs_kdf.constants import PEPPER


def qstretch(password: str, salt: bytes, pepper: bytes = PEPPER) -> bytes:
    """Return 256-bit stretched digest using a double hash."""
    data = password.encode() + salt + pepper
    digest = hashlib.sha512(data).digest()
    return hashlib.sha256(digest).digest()


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
