import subprocess
import sys

import qs_kdf


def test_hash_password_length():
    salt = b"\x01" * 16
    backend = qs_kdf.TestBackend()
    digest = qs_kdf.hash_password("pw", salt, backend=backend)
    assert len(digest) == 32


def test_cli_output():
    result = subprocess.run(
        [sys.executable, "-m", "qs_kdf", "hash", "pw", "--salt", "01" * 16],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip()
