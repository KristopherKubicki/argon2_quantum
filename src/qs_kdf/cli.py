"""Command-line interface for hashing and verifying passwords."""

import argparse

from .core import LocalBackend, hash_password, lambda_handler, verify_password


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and hash or verify a password.

    Args:
        argv: Optional list of command-line arguments.

    Returns:
        int: ``0`` on success.
    """

    parser = argparse.ArgumentParser(prog="qs_kdf")
    sub = parser.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hash")
    h.add_argument("password")
    h.add_argument("--salt", required=True)
    h.add_argument("--cloud", action="store_true")

    v = sub.add_parser("verify")
    v.add_argument("password")
    v.add_argument("--salt", required=True)
    v.add_argument("--digest", required=True)

    args = parser.parse_args(argv)
    salt = bytes.fromhex(args.salt)
    if args.cmd == "hash":
        if args.cloud:
            response = lambda_handler(
                {"password": args.password, "salt": args.salt}, None
            )
            digest_hex = response["digest"]
        else:
            backend = LocalBackend()
            digest_hex = hash_password(args.password, salt, backend=backend).hex()
        print(digest_hex)
    else:
        digest = bytes.fromhex(args.digest)
        backend = LocalBackend()
        ok = verify_password(args.password, salt, digest, backend=backend)
        print("OK" if ok else "NOPE")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
