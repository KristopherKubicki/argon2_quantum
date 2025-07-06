import os
os.environ.setdefault("QS_PEPPER", "x" * 32)

import qs_kdf


def test_qstretch_deterministic():
    salt = b"\x00" * 16
    digest1 = qs_kdf.qstretch("password", salt)
    digest2 = qs_kdf.qstretch("password", salt)
    assert digest1 == digest2
    assert len(digest1) == 32


def test_hash_password_length():
    salt = b"\x01" * 16
    digest = qs_kdf.hash_password("pw", salt)
    assert len(digest) == 32
