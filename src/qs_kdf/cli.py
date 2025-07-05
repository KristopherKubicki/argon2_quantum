"""Command-line interface for hashing and verifying passwords."""

import argparse
import os

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
    h.add_argument(
        "--pepper",
        help="hex encoded pepper or from QS_KDF_PEPPER env variable",
    )

    v = sub.add_parser("verify")
    v.add_argument("password")
    v.add_argument("--salt", required=True)
    v.add_argument("--digest", required=True)
    v.add_argument(
        "--pepper",
        help="hex encoded pepper or from QS_KDF_PEPPER env variable",
    )

    args = parser.parse_args(argv)
    try:
        salt = bytes.fromhex(args.salt)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid hex value for --salt: {args.salt}"
        ) from exc
    pepper_hex = args.pepper or os.environ.get("QS_KDF_PEPPER")
    needs_pepper = args.cmd == "verify" or (args.cmd == "hash" and not args.cloud)
    pepper: bytes = b""
    if needs_pepper:
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
    if args.cmd == "hash":
        if args.cloud:
            response = lambda_handler(
                {"password": args.password, "salt": args.salt}, None
            )
            digest_hex = response["digest"]
        else:
            backend = LocalBackend()
            digest_hex = hash_password(
                args.password, salt, backend=backend, pepper=pepper
            ).hex()
        print(digest_hex)
    else:
        try:
            digest = bytes.fromhex(args.digest)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"invalid hex value for --digest: {args.digest}"
            ) from exc
        backend = LocalBackend()
        ok = verify_password(
            args.password, salt, digest, backend=backend, pepper=pepper
        )
        print("OK" if ok else "NOPE")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
