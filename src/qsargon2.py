"""Quantum stretch and Argon2 wrapper."""

from __future__ import annotations

import base64
import hashlib
try:
    from argon2.low_level import Type, hash_secret_raw
except Exception:  # pragma: no cover - optional fallback
    class Type:  # type: ignore[no-redef]
        ID = 2

    def hash_secret_raw(
        password: bytes,
        salt: bytes,
        time_cost: int,
        memory_cost: int,
        parallelism: int,
        hash_len: int,
        type: int,
    ) -> bytes:
        return hashlib.scrypt(
            password,
            salt=salt,
            n=2**14,
            r=8,
            p=parallelism,
            dklen=hash_len,
        )
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
    """Hash ``password`` using qstretch + Argon2id.

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
    digest = hash_secret_raw(
        pre,
        salt,
        time_cost=2,
        memory_cost=16_384,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )
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
