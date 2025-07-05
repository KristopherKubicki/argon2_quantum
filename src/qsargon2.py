"""Compatibility wrappers for qs_kdf."""

import argparse
import base64
import os
import secrets

from qs_kdf.core import hash_password, qstretch

__all__ = ["qstretch", "hash_password", "main"]


def main(argv: list[str] | None = None) -> int:
    """Legacy CLI for hashing a password."""

    parser = argparse.ArgumentParser(prog="qsargon2")
    parser.add_argument("password")
    parser.add_argument("--salt")
    parser.add_argument(
        "--pepper",
        help="hex encoded pepper or from QS_KDF_PEPPER env variable",
    )
    args = parser.parse_args(argv)
    salt = bytes.fromhex(args.salt) if args.salt else secrets.token_bytes(16)
    pepper_hex = args.pepper or os.environ.get("QS_KDF_PEPPER")
    if pepper_hex is None:
        raise argparse.ArgumentTypeError(
            "pepper required via --pepper or QS_KDF_PEPPER"
        )
    try:
        pepper = bytes.fromhex(pepper_hex)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid hex value for --pepper: {pepper_hex}"
        ) from exc
    digest = hash_password(args.password, salt, pepper=pepper)
    print(base64.b64encode(digest).decode())
    return 0


if __name__ == "__main__":  # pragma: no cover
    main()
