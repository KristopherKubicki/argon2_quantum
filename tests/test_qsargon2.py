import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import qsargon2


def test_qstretch_deterministic():
    salt = b"\x00" * 16
    digest1 = qsargon2.qstretch("password", salt)
    digest2 = qsargon2.qstretch("password", salt)
    assert digest1 == digest2


def test_hash_password_length():
    salt = b"\x01" * 16
    digest = qsargon2.hash_password("pw", salt)
    assert len(digest) == 32
