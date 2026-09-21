"""CLI for versioned records; passwords come from a prompt or bounded stdin."""

import argparse
import getpass
import json
import os
from pathlib import Path
import sys

from . import __version__
from .records import LocalPepper, PasswordHasher, ProviderUnavailable
from .service import _configured_hasher, _unique_object


def _local_hasher(keyring_path: str | None) -> PasswordHasher:
    if keyring_path:
        with Path(keyring_path).open(encoding="utf-8") as stream:
            raw = stream.read(8193)
        if len(raw) > 8192:
            raise ValueError("keyring file exceeds 8192 characters")
        config = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(config, dict) or set(config) != {"current", "keys"}:
            raise ValueError("keyring must contain current and keys")
        values = config["keys"]
        if not isinstance(values, dict) or not 1 <= len(values) <= 16:
            raise ValueError("keyring must contain 1..16 keys")
        current = config["current"]
    else:
        current = os.environ.get("QS_CURRENT_KEY_ID", "local-1")
        value = os.environ.get("QS_PEPPER_HEX", "")
        values = {current: value}
    if any(not isinstance(v, str) or len(v) != 64 for v in values.values()):
        raise ValueError(
            "provide a keyring or QS_PEPPER_HEX with 64 hex characters per key"
        )
    try:
        keys = {k: bytes.fromhex(v) for k, v in values.items()}
    except ValueError:
        raise ValueError("pepper keys must be hexadecimal") from None
    return PasswordHasher(LocalPepper(keys), current)


def _password(args) -> str:
    if args.password_stdin:
        value = sys.stdin.readline(1026)
        if value.endswith("\n"):
            value = value[:-1]
            if value.endswith("\r"):
                value = value[:-1]
        return value
    value = getpass.getpass("Password: ")
    if args.cmd == "hash" and value != getpass.getpass("Confirm password: "):
        raise ValueError("passwords do not match")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qs_kdf")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for command in ("hash", "verify", "migrate-legacy"):
        p = sub.add_parser(command)
        p.add_argument("--password-stdin", action="store_true")
        group = p.add_mutually_exclusive_group()
        group.add_argument("--keyring", help="server-side JSON pepper keyring file")
        group.add_argument("--kms", action="store_true", help="use QS_KMS_KEYS keyring")
        if command == "verify":
            p.add_argument("--record", required=True)
        if command == "hash":
            p.add_argument(
                "--quantum-device-arn", help="optional enrollment entropy only"
            )
        if command == "migrate-legacy":
            p.add_argument("--salt", required=True)
            p.add_argument("--digest", required=True)
            p.add_argument("--time-cost", type=int, default=3)
            p.add_argument("--memory-cost", type=int, default=262_144)
            p.add_argument("--parallelism", type=int, default=4)
    args = parser.parse_args(argv)
    try:
        hasher = (
            _configured_hasher(
                os.environ.get("QS_KMS_KEYS", ""),
                os.environ.get("QS_CURRENT_KEY_ID", ""),
            )
            if args.kms
            else _local_hasher(args.keyring)
        )
        password = _password(args)
        if args.cmd == "verify":
            valid = hasher.verify(password, args.record)
            print("OK" if valid else "NOPE")
            return 0 if valid else 1
        if args.cmd == "migrate-legacy":
            from .legacy import verify_local

            if not verify_local(
                password,
                args.salt,
                args.digest,
                time_cost=args.time_cost,
                memory_cost=args.memory_cost,
                parallelism=args.parallelism,
            ):
                print("NOPE")
                return 1
        supplemental = b""
        if args.cmd == "hash" and args.quantum_device_arn:
            from .core import BraketBackend
            from .records import password_bytes

            password_bytes(password)  # Validate before spending QPU time.
            supplemental = BraketBackend(device_arn=args.quantum_device_arn).run(b"")
        print(hasher.hash(password, supplemental_entropy=supplemental))
        return 0
    except ProviderUnavailable:
        print("Protected key service unavailable", file=sys.stderr)
        return 3
    except (ValueError, TypeError, RuntimeError, OSError, EOFError) as exc:
        # These are local validation/configuration messages, not password payloads.
        parser.error(str(exc))
    return 2
