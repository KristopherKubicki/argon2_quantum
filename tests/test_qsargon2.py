import os
import sys
import base64

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import qsargon2

os.environ.setdefault(
    "PEPPER",
    base64.b64encode(b"fixedPepper32B012345678901234567").decode(),
)


def test_qstretch_deterministic():
    salt = b"\x00" * 16
    digest1 = qsargon2.qstretch("password", salt)
    digest2 = qsargon2.qstretch("password", salt)
    assert digest1 == digest2
    assert len(digest1) == 32


def test_hash_password_length():
    salt = b"\x01" * 16
    digest = qsargon2.hash_password("pw", salt)
    assert len(digest) == 32
