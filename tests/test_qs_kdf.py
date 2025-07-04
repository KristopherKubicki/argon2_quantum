import contextlib
import hashlib
import importlib
import io
import sys
import time
import types


def _fake_hash_secret_raw(
    pw, salt, time_cost, memory_cost, parallelism, hash_len, type, *, secret=None
):
    return hashlib.scrypt(
        pw if secret is None else pw + secret,
        salt=salt,
        n=2**14,
        r=8,
        p=parallelism,
        dklen=hash_len,
    )


def _load_modules(monkeypatch):
    stub = types.SimpleNamespace(
        Type=types.SimpleNamespace(ID=2),
        hash_secret_raw=_fake_hash_secret_raw,
    )
    monkeypatch.setitem(sys.modules, "argon2.low_level", stub)
    qs_kdf = importlib.import_module("qs_kdf")
    cli_module = importlib.import_module("qs_kdf.cli")
    return qs_kdf, cli_module


def test_hash_password_length(monkeypatch):
    qs_kdf, _ = _load_modules(monkeypatch)
    salt = b"\x01" * 16
    backend = qs_kdf.TestBackend()
    digest = qs_kdf.hash_password("pw", salt, backend=backend)
    assert len(digest) == 32


def _run_cli(cli_module, argv: list[str]) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli_module.main(argv)
    return buf.getvalue().strip()


def test_cli_output_local(monkeypatch):
    _, cli_module = _load_modules(monkeypatch)
    out = _run_cli(cli_module, ["hash", "pw", "--salt", "01" * 16])
    assert out


def test_cli_output_cloud(monkeypatch):
    qs_kdf, cli_module = _load_modules(monkeypatch)

    def fake_handler(event: dict, _ctx: object) -> dict:
        return {"digest": "deadbeef"}

    monkeypatch.setattr(cli_module, "lambda_handler", fake_handler)
    out = _run_cli(cli_module, ["hash", "pw", "--salt", "01" * 16, "--cloud"])
    assert out == "deadbeef"


def test_timing_attack(monkeypatch):
    qs_kdf, _ = _load_modules(monkeypatch)
    salt = b"\x02" * 16
    backend = qs_kdf.TestBackend()
    start_good = time.perf_counter()
    qs_kdf.hash_password("pw", salt, backend=backend)
    good = time.perf_counter() - start_good
    start_bad = time.perf_counter()
    qs_kdf.hash_password("bad", salt, backend=backend)
    bad = time.perf_counter() - start_bad
    assert abs(good - bad) <= 0.05


def test_verify_password(monkeypatch):
    qs_kdf, _ = _load_modules(monkeypatch)
    salt = b"\x03" * 16
    backend = qs_kdf.TestBackend()
    digest = qs_kdf.hash_password("pw", salt, backend=backend)
    assert qs_kdf.verify_password("pw", salt, digest, backend=backend)
    assert not qs_kdf.verify_password("bad", salt, digest, backend=backend)


def test_cli_verify(monkeypatch):
    qs_kdf, cli_module = _load_modules(monkeypatch)
    backend = qs_kdf.LocalBackend()
    salt = b"\x04" * 16
    digest = qs_kdf.hash_password("pw", salt, backend=backend)
    out = _run_cli(
        cli_module,
        [
            "verify",
            "pw",
            "--salt",
            "04" * 16,
            "--digest",
            digest.hex(),
        ],
    )
    assert out == "OK"


def test_braket_backend(monkeypatch):
    qs_kdf, _ = _load_modules(monkeypatch)

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
    assert result == b"\x42"

    backend2 = qs_kdf.BraketBackend(device=FakeDevice("01000010"), num_bytes=2)
    result2 = backend2.run(b"seed")
    assert result2 == b"\x42\x42"
