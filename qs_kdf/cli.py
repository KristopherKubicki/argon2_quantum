import argparse

from .core import BraketBackend, LocalBackend, hash_password


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qs_kdf")
    sub = parser.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hash")
    h.add_argument("password")
    h.add_argument("--salt", required=True)
    h.add_argument("--cloud", action="store_true")
    args = parser.parse_args(argv)
    salt = bytes.fromhex(args.salt)
    backend = BraketBackend() if args.cloud else LocalBackend()
    digest = hash_password(args.password, salt, backend=backend)
    print(digest.hex())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
