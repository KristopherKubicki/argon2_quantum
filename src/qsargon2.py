"""Compatibility wrappers for qs_kdf."""

import argparse
import base64
import secrets

from qs_kdf.core import hash_password, qstretch

__all__ = ["qstretch", "hash_password", "main"]


def main(argv: list[str] | None = None) -> int:
    """Legacy CLI for hashing a password."""

    parser = argparse.ArgumentParser(prog="qsargon2")
    parser.add_argument("password")
    parser.add_argument("--salt")
    args = parser.parse_args(argv)
    salt = bytes.fromhex(args.salt) if args.salt else secrets.token_bytes(16)
    digest = hash_password(args.password, salt)
    print(base64.b64encode(digest).decode())
    return 0


if __name__ == "__main__":  # pragma: no cover
    main()
