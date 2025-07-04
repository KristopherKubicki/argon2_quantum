import contextlib
import importlib
import io
import random
import sys
import time
import types

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
    assert abs(good - bad) <= 0.05


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


def test_hash_deterministic_braket(monkeypatch):
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

    class SeededDevice:
        def run(self, circuit, shots: int, rng_seed: int | None = None):
            assert shots == 1
            r = random.Random(rng_seed)
            bits = "".join("1" if r.random() > 0.5 else "0" for _ in range(8))
            return FakeTask(bits)

    monkeypatch.setitem(
        sys.modules,
        "braket.circuits",
        types.SimpleNamespace(Circuit=lambda: FakeCircuit()),
    )

    backend = qs_kdf.BraketBackend(device=SeededDevice())
    salt = b"\x05" * 16
    digest1 = qs_kdf.hash_password("pw", salt, backend=backend)
    digest2 = qs_kdf.hash_password("pw", salt, backend=backend)
    assert digest1 == digest2


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

    class SeededDevice:
        def run(self, circuit, shots: int, rng_seed: int | None = None):
            assert shots == 1
            r = random.Random(rng_seed)
            bits = "".join("1" if r.random() > 0.5 else "0" for _ in range(8))
            return FakeTask(bits)

    monkeypatch.setitem(
        sys.modules,
        "braket.circuits",
        types.SimpleNamespace(Circuit=lambda: FakeCircuit()),
    )

    backend = qs_kdf.BraketBackend(device=SeededDevice())
    result1 = backend.run(b"seed")
    result2 = backend.run(b"seed")
    assert result1 == result2

    backend2 = qs_kdf.BraketBackend(device=SeededDevice(), num_bytes=2)
    result3 = backend2.run(b"seed")
    result4 = backend2.run(b"seed")
    assert result3 == result4
