"""Command-line interface for hashing and verifying passwords."""

import argparse
import os

import qs_kdf

from .constants import (
    MAX_PASSWORD_BYTES,
    MAX_SALT_BYTES,
    MIN_TIME_COST,
    MAX_TIME_COST,
    MIN_MEMORY_COST,
    MAX_MEMORY_COST,
    MIN_PARALLELISM,
    MAX_PARALLELISM,
)

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
    if not (MIN_TIME_COST <= args.time_cost <= MAX_TIME_COST):
        parser.error(f"--time-cost must be between {MIN_TIME_COST} and {MAX_TIME_COST}")
    if not (MIN_MEMORY_COST <= args.memory_cost <= MAX_MEMORY_COST):
        parser.error(
            f"--memory-cost must be between {MIN_MEMORY_COST} and {MAX_MEMORY_COST}"
        )
    if not (MIN_PARALLELISM <= args.parallelism <= MAX_PARALLELISM):
        parser.error(
            f"--parallelism must be between {MIN_PARALLELISM} and {MAX_PARALLELISM}"
        )
    if args.cmd == "hash":
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
            pepper_env = os.getenv("QS_PEPPER")
            if pepper_env is None:
                parser.error("QS_PEPPER environment variable required")
            pepper = pepper_env.encode()
            if len(pepper) == 0:
                parser.error("QS_PEPPER must not be empty")
            if len(pepper) != 32:
                parser.error("QS_PEPPER must be 32 bytes")
            backend = LocalBackend()
            digest_hex = hash_password(
                args.password,
                salt,
                backend=backend,
                pepper=pepper,
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
        if len(digest) != 32:
            raise argparse.ArgumentTypeError(
                f"--digest must decode to 32 bytes, got {len(digest)}"
            )
        pepper_env = os.getenv("QS_PEPPER")
        if pepper_env is None:
            parser.error("QS_PEPPER environment variable required")
        pepper = pepper_env.encode()
        if len(pepper) == 0:
            parser.error("QS_PEPPER must not be empty")
        if len(pepper) != 32:
            parser.error("QS_PEPPER must be 32 bytes")
        backend = LocalBackend()
        ok = verify_password(
            args.password,
            salt,
            digest,
            backend=backend,
            pepper=pepper,
            time_cost=args.time_cost,
            memory_cost=args.memory_cost,
            parallelism=args.parallelism,
        )
        print("OK" if ok else "NOPE")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
