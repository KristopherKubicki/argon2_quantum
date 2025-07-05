import base64
import contextlib
import io
import runpy
import sys

import qsargon2


def _run_cli(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        old_argv = sys.argv
        sys.argv = ["qsargon2", *argv]
        try:
            code = 0
            try:
                runpy.run_module("qsargon2", run_name="__main__")
            except SystemExit as exc:  # pragma: no cover - CLI exit
                code = exc.code if exc.code is not None else 0
        finally:
            sys.argv = old_argv
    return code, buf.getvalue().strip()


def test_entry_script_deterministic():
    salt = b"\x05" * 16
    salt_hex = salt.hex()
    code1, out1 = _run_cli(["pw", "--salt", salt_hex])
    code2, out2 = _run_cli(["pw", "--salt", salt_hex])
    expected = base64.b64encode(qsargon2.hash_password("pw", salt)).decode()
    assert code1 == code2 == 0
    assert out1 == out2 == expected
