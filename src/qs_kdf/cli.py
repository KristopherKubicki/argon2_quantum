"""Command-line interface for hashing and verifying passwords."""

import argparse
import os

import qs_kdf

from .constants import MAX_PASSWORD_BYTES, MAX_SALT_BYTES, MAX_NUM_BYTES

from .core import LocalBackend, hash_password, lambda_handler, verify_password


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and hash or verify a password.

    Args:
        argv: Optional list of command-line arguments.

    Returns:
        int: ``0`` on success, ``1`` when password verification fails.
    """

    parser = argparse.ArgumentParser(prog="qs_kdf")
    parser.add_argument("--version", action="version", version=qs_kdf.__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hash")
    h.add_argument("password")
    h.add_argument("--salt")
    h.add_argument("--cloud", action="store_true")
    h.add_argument(
        "--device-arn", default="arn:aws:braket:::device/qpu/ionq/ionQdevice"
    )
    h.add_argument("--num-bytes", type=int, default=10)
    h.add_argument("--time-cost", type=int, default=3)
    h.add_argument("--memory-cost", type=int, default=262_144)
    h.add_argument("--parallelism", type=int, default=4)

    v = sub.add_parser("verify")
    v.add_argument("password")
    v.add_argument("--salt", required=True)
    v.add_argument("--digest", required=True)
    v.add_argument("--time-cost", type=int, default=3)
    v.add_argument("--memory-cost", type=int, default=262_144)
    v.add_argument("--parallelism", type=int, default=4)

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
        if args.num_bytes <= 0:
            parser.error("--num-bytes must be a positive integer")
        if args.num_bytes > MAX_NUM_BYTES:
            parser.error(f"--num-bytes may not exceed {MAX_NUM_BYTES}")
        if args.cloud:
            required = ["KMS_KEY_ID", "PEPPER_CIPHERTEXT", "REDIS_HOST"]
            missing = [v for v in required if v not in os.environ]
            if missing:
                parser.error(
                    "--cloud requires environment variables: " + ", ".join(missing)
                )
            response = lambda_handler(
                {
                    "password": args.password,
                    "salt": salt_hex,
                    "device_arn": args.device_arn,
                    "num_bytes": args.num_bytes,
                },
                None,
            )
            digest_hex = response["digest"]
        else:
            backend = LocalBackend()
            digest_hex = hash_password(
                args.password,
                salt,
                backend=backend,
                time_cost=args.time_cost,
                memory_cost=args.memory_cost,
                parallelism=args.parallelism,
            ).hex()
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
        ok = verify_password(
            args.password,
            salt,
            digest,
            backend=backend,
            time_cost=args.time_cost,
            memory_cost=args.memory_cost,
            parallelism=args.parallelism,
        )
        print("OK" if ok else "NOPE")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
