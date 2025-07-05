import argparse
import contextlib
import importlib
import io
import sys
import time
import types

import pytest

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
    assert abs(good - bad) <= 0.1


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


def test_cli_verify_nope():
    backend = qs_kdf.LocalBackend()
    salt = b"\x05" * 16
    qs_kdf.hash_password("pw", salt, backend=backend)
    out = _run_cli(
        [
            "verify",
            "pw",
            "--salt",
            "05" * 16,
            "--digest",
            "00" * 32,
        ]
    )
    assert out == "NOPE"


def test_braket_backend(monkeypatch):
    class FakeCircuit:
        def h(self, *args, **kwargs):
            return self

        def measure(self, *args, **kwargs):
            return self

    class FakeResult:
        def __init__(self, bits: str) -> None:
            self.measurement_counts = {bits: 1}

    class FakeTask:
        def __init__(self, bits: str) -> None:
            self._bits = bits

        def result(self):
            return FakeResult(self._bits)

    class FakeDevice:
        def __init__(self, bits: str) -> None:
            self.bits = bits

        def run(self, circuit, shots: int):
            assert shots == 1
            return FakeTask(self.bits)

    monkeypatch.setitem(
        sys.modules,
        "braket.circuits",
        types.SimpleNamespace(Circuit=lambda: FakeCircuit()),
    )

    backend = qs_kdf.BraketBackend(device=FakeDevice("01000010"))
    result = backend.run(b"seed")
    assert result == b"\x42" * 10

    backend2 = qs_kdf.BraketBackend(device=FakeDevice("01000010"), num_bytes=2)
    result2 = backend2.run(b"seed")
    assert result2 == b"\x42\x42"


def test_braket_backend_unavailable(monkeypatch):
    class FailingDevice:
        def __init__(self, *args, **kwargs) -> None:
            raise Exception("unavailable")

    monkeypatch.setitem(
        sys.modules,
        "braket.aws",
        types.SimpleNamespace(AwsDevice=FailingDevice),
    )

    backend = qs_kdf.BraketBackend(device=None)
    with pytest.raises(RuntimeError):
        backend.run(b"seed")


def test_cli_invalid_salt():
    with pytest.raises(argparse.ArgumentTypeError):
        cli_module.main(["hash", "pw", "--salt", "zz"])


def test_cli_invalid_digest():
    with pytest.raises(argparse.ArgumentTypeError):
        cli_module.main(["verify", "pw", "--salt", "01" * 16, "--digest", "zz"])
