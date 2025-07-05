import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import base64
import contextlib
import io

import qsargon2


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


def test_hash_password_random_salt(monkeypatch):
    calls = []

    def fake_token_bytes(n: int) -> bytes:
        calls.append(n)
        return b"\xaa" * n

    monkeypatch.setattr(qsargon2.secrets, "token_bytes", fake_token_bytes)
    digest_random = qsargon2.hash_password("pw")
    assert calls == [16]

    digest_fixed = qsargon2.hash_password("pw", b"\xaa" * 16)
    assert digest_random == digest_fixed


def _run_cli(argv: list[str], monkeypatch) -> str:
    buf = io.StringIO()
    monkeypatch.setattr(sys, "argv", ["qsargon2"] + argv)
    with contextlib.redirect_stdout(buf):
        qsargon2.main()
    return buf.getvalue().strip()


def test_cli_output(monkeypatch):
    out = _run_cli(["pw", "--salt", "01" * 16], monkeypatch)
    assert out


def test_cli_random_salt(monkeypatch):
    monkeypatch.setattr(qsargon2.secrets, "token_bytes", lambda n: b"\x33" * n)
    out = _run_cli(["pw"], monkeypatch)
    digest = qsargon2.hash_password("pw", b"\x33" * 16)
    expected = base64.b64encode(digest).decode()
    assert out == expected
