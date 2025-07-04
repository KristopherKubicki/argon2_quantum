import contextlib
import importlib
import io
import time

import qs_kdf

cli_module = importlib.import_module("qs_kdf.cli")


def test_hash_password_length():
    salt = b"\x01" * 16
    backend = qs_kdf.TestBackend()
    digest = qs_kdf.hash_password("pw", salt, backend=backend)
    assert len(digest) == 32


def _run_cli(argv: list[str]) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli_module.main(argv)
    return buf.getvalue().strip()


def test_cli_output_local():
    out = _run_cli(["hash", "pw", "--salt", "01" * 16])
    assert out


def test_cli_output_cloud(monkeypatch):
    def fake_handler(event: dict, _ctx: object) -> dict:
        return {"digest": "deadbeef"}

    monkeypatch.setattr(cli_module, "lambda_handler", fake_handler)
    out = _run_cli(["hash", "pw", "--salt", "01" * 16, "--cloud"])
    assert out == "deadbeef"


def test_timing_attack():
    salt = b"\x02" * 16
    backend = qs_kdf.TestBackend()
    start_good = time.perf_counter()
    qs_kdf.hash_password("pw", salt, backend=backend)
    good = time.perf_counter() - start_good
    start_bad = time.perf_counter()
    qs_kdf.hash_password("bad", salt, backend=backend)
    bad = time.perf_counter() - start_bad
    assert abs(good - bad) <= 0.01


def test_verify_password():
    salt = b"\x03" * 16
    backend = qs_kdf.TestBackend()
    digest = qs_kdf.hash_password("pw", salt, backend=backend)
    assert qs_kdf.verify_password("pw", salt, digest, backend=backend)
    assert not qs_kdf.verify_password("bad", salt, digest, backend=backend)


def test_cli_verify():
    backend = qs_kdf.LocalBackend()
    salt = b"\x04" * 16
    digest = qs_kdf.hash_password("pw", salt, backend=backend)
    out = _run_cli(
        [
            "verify",
            "pw",
            "--salt",
            "04" * 16,
            "--digest",
            digest.hex(),
        ]
    )
    assert out == "OK"


def test_kms_backend(monkeypatch):
    class FakeKMS:
        def generate_random(self, NumberOfBytes: int):
            assert NumberOfBytes == 1
            return {"Plaintext": b"\x42"}

    backend = qs_kdf.KmsBackend(kms_client=FakeKMS())
    result = backend.run(b"seed")
    assert result == b"\x42"
