"""Command-line interface for hashing and verifying passwords."""

import argparse
import os

from .constants import MAX_PASSWORD_BYTES, MAX_SALT_BYTES

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
    h.add_argument("--salt")
    h.add_argument("--cloud", action="store_true")

    v = sub.add_parser("verify")
    v.add_argument("password")
    v.add_argument("--salt", required=True)
    v.add_argument("--digest", required=True)

    args = parser.parse_args(argv)
    if args.salt is None:
        salt = os.urandom(16)
        salt_hex = salt.hex()
    else:
        try:
            salt = bytes.fromhex(args.salt)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"invalid hex value for --salt: {args.salt}"
            ) from exc
        salt_hex = args.salt
    if len(args.password.encode()) > MAX_PASSWORD_BYTES:
        parser.error(f"password exceeds {MAX_PASSWORD_BYTES} bytes")
    if len(salt) > MAX_SALT_BYTES:
        parser.error(f"salt exceeds {MAX_SALT_BYTES} bytes")
    if args.cmd == "hash":
        if args.cloud:
            required = ["KMS_KEY_ID", "PEPPER_CIPHERTEXT", "REDIS_HOST"]
            missing = [v for v in required if v not in os.environ]
            if missing:
                parser.error(
                    "--cloud requires environment variables: " + ", ".join(missing)
                )
            response = lambda_handler(
                {"password": args.password, "salt": salt_hex}, None
            )
            digest_hex = response["digest"]
        else:
            backend = LocalBackend()
            digest_hex = hash_password(args.password, salt, backend=backend).hex()
        if args.salt is None:
            print(f"{salt_hex} {digest_hex}")
        else:
            print(digest_hex)
    else:
        try:
            digest = bytes.fromhex(args.digest)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"invalid hex value for --digest: {args.digest}"
            ) from exc
        backend = LocalBackend()
        ok = verify_password(args.password, salt, digest, backend=backend)
        print("OK" if ok else "NOPE")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
