import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import subprocess

import qs_kdf


def test_quantum_bits_deterministic():
    seed = b"\x00" * 64
    out1 = qs_kdf._quantum_bits(seed)
    out2 = qs_kdf._quantum_bits(seed)
    assert out1 == out2


def test_hash_password_length():
    salt = b"\x01" * 16
    digest = qs_kdf.hash_password("pw", salt)
    assert len(digest) == 32


def test_cli_output():
    result = subprocess.run(
        [sys.executable, "qs_kdf.py", "pw", "--salt", "01" * 16],
        capture_output=True,
        check=True,
        text=True,
    )
    assert result.stdout.strip()
