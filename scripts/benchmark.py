"""Reproducible local baseline; no AWS/QPU calls or real credentials."""

import argparse
import json
import platform
import secrets
import statistics
import time

from qs_kdf import LocalPepper, PasswordHasher


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=30)
    args = parser.parse_args()
    if not 5 <= args.samples <= 1000:
        parser.error("samples must be between 5 and 1000")
    hasher = PasswordHasher(
        LocalPepper({"benchmark": secrets.token_bytes(32)}), "benchmark"
    )
    password = "synthetic benchmark passphrase"
    record = hasher.hash(password)
    elapsed = []
    for _ in range(args.samples):
        start = time.perf_counter()
        if not hasher.verify(password, record):
            raise RuntimeError("verification failed")
        elapsed.append((time.perf_counter() - start) * 1000)
    elapsed.sort()
    print(
        json.dumps(
            {
                "python": platform.python_version(),
                "platform": platform.platform(),
                "samples": args.samples,
                "memory_kib": 65536,
                "passes": 3,
                "lanes": 4,
                "median_ms": round(statistics.median(elapsed), 2),
                "p95_ms": round(
                    elapsed[max(0, (95 * len(elapsed) + 99) // 100 - 1)], 2
                ),
                "max_ms": round(max(elapsed), 2),
                "scope": (
                    "single-process local HMAC; "
                    "excludes KMS, network and Lambda cold starts"
                ),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
