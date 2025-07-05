import base64
import contextlib
import io
import runpy
import sys

import qsargon2


def _run_cli(argv: list[str]) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        old_argv = sys.argv
        sys.argv = ["qsargon2", *argv]
        try:
            runpy.run_module("qsargon2", run_name="__main__")
        finally:
            sys.argv = old_argv
    return buf.getvalue().strip()


def test_entry_script_deterministic():
    salt = b"\x05" * 16
    salt_hex = salt.hex()
    out1 = _run_cli(["pw", "--salt", salt_hex])
    out2 = _run_cli(["pw", "--salt", salt_hex])
    expected = base64.b64encode(qsargon2.hash_password("pw", salt)).decode()
    assert out1 == out2 == expected
