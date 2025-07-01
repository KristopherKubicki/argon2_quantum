import argparse

from .core import LocalBackend, hash_password, lambda_handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qs_kdf")
    sub = parser.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hash")
    h.add_argument("password")
    h.add_argument("--salt", required=True)
    h.add_argument("--cloud", action="store_true")
    args = parser.parse_args(argv)
    salt = bytes.fromhex(args.salt)
    if args.cloud:
        response = lambda_handler({"password": args.password, "salt": args.salt}, None)
        digest_hex = response["digest"]
    else:
        backend = LocalBackend()
        digest_hex = hash_password(args.password, salt, backend=backend).hex()
    print(digest_hex)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
