import argparse
import contextlib
import importlib
import io
import sys
import time
import types
import hashlib
from argon2.low_level import hash_secret_raw, Type
from qs_kdf.constants import PEPPER

import pytest

import qs_kdf

cli_module = importlib.import_module("qs_kdf.cli")


@pytest.fixture()
def _pepper(monkeypatch):
    monkeypatch.setenv("QS_PEPPER", "x" * 32)
    import qs_kdf.constants as constants
    monkeypatch.setattr(constants, "PEPPER", b"x" * 32, raising=False)
    import qs_kdf.core as core
    monkeypatch.setattr(core, "PEPPER", b"x" * 32, raising=False)


def test_hash_password_length():
    salt = b"\x01" * 16
    backend = qs_kdf.TestBackend()
    digest = qs_kdf.hash_password("pw", salt, backend=backend)
    assert len(digest) == 32


def _legacy_hash_password(
    password: str, salt: bytes, backend: qs_kdf.TestBackend
) -> bytes:
    pre = hashlib.sha512(password.encode() + salt + PEPPER).digest()
    pre = hashlib.sha256(pre).digest()
    quantum = backend.run(pre)
    new_salt = salt + quantum
    return hash_secret_raw(
        password.encode(),
        new_salt,
        time_cost=3,
        memory_cost=262_144,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )


def test_hash_password_compatibility():
    salt = b"\x09" * 16
    backend = qs_kdf.TestBackend()
    new_digest = qs_kdf.hash_password("pw", salt, backend=backend)
    old_digest = _legacy_hash_password("pw", salt, backend)
    assert new_digest == old_digest


def _run_cli(argv: list[str]) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli_module.main(argv)
    return buf.getvalue().strip()


def test_cli_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli_module.main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert qs_kdf.__version__ in captured.out


def test_cli_output_local(_pepper):
    out = _run_cli(["hash", "pw", "--salt", "01" * 16])
    assert out


def test_cli_generates_salt(_pepper):
    out = _run_cli(["hash", "pw"])
    salt_hex, digest_hex = out.split()
    assert len(salt_hex) == 32
    assert len(digest_hex) == 64
    verify_out = _run_cli(["verify", "pw", "--salt", salt_hex, "--digest", digest_hex])
    assert verify_out == "OK"


def test_cli_output_cloud(monkeypatch):
    def fake_handler(event: dict, _ctx: object) -> dict:
        return {"digest": "deadbeef"}

    monkeypatch.setattr(cli_module, "lambda_handler", fake_handler)
    monkeypatch.setenv("KMS_KEY_ID", "k")
    monkeypatch.setenv("PEPPER_CIPHERTEXT", "c")
    monkeypatch.setenv("REDIS_HOST", "r")
    out = _run_cli(["hash", "pw", "--salt", "01" * 16, "--cloud"])
    assert out == "deadbeef"


def test_cli_device_options(monkeypatch):
    captured: dict[str, dict] = {}

    def fake_handler(event: dict, _ctx: object) -> dict:
        captured["event"] = event
        return {"digest": "bead"}

    monkeypatch.setattr(cli_module, "lambda_handler", fake_handler)
    monkeypatch.setenv("KMS_KEY_ID", "k")
    monkeypatch.setenv("PEPPER_CIPHERTEXT", "c")
    monkeypatch.setenv("REDIS_HOST", "r")
    out = _run_cli(
        [
            "hash",
            "pw",
            "--salt",
            "01" * 16,
            "--cloud",
            "--device-arn",
            "arn:custom",
            "--num-bytes",
            "2",
        ]
    )
    assert out == "bead"
    assert captured["event"]["device_arn"] == "arn:custom"
    assert captured["event"]["num_bytes"] == 2


def test_cli_custom_params(monkeypatch, _pepper):
    called: dict[str, tuple[int, int, int]] = {}

    def fake_hash_password(
        password: str,
        salt: bytes,
        backend=None,
        pepper=None,
        time_cost: int = 3,
        memory_cost: int = 262_144,
        parallelism: int = 4,
    ) -> bytes:
        called["params"] = (time_cost, memory_cost, parallelism)
        return b"\x00" * 32

    monkeypatch.setattr(cli_module, "hash_password", fake_hash_password)
    out = _run_cli(
        [
            "hash",
            "pw",
            "--salt",
            "01" * 16,
            "--time-cost",
            "5",
            "--memory-cost",
            "64",
            "--parallelism",
            "2",
        ]
    )
    assert called["params"] == (5, 64, 2)
    assert out == "00" * 32


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


def test_cli_verify(_pepper):
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


def test_cli_verify_custom_params(monkeypatch, _pepper):
    called: dict[str, tuple[int, int, int]] = {}

    def fake_verify_password(
        password: str,
        salt: bytes,
        digest: bytes,
        backend=None,
        pepper=None,
        time_cost: int = 3,
        memory_cost: int = 262_144,
        parallelism: int = 4,
    ) -> bool:
        called["params"] = (time_cost, memory_cost, parallelism)
        return True

    monkeypatch.setattr(cli_module, "verify_password", fake_verify_password)
    out = _run_cli(
        [
            "verify",
            "pw",
            "--salt",
            "04" * 16,
            "--digest",
            "00" * 32,
            "--time-cost",
            "5",
            "--memory-cost",
            "64",
            "--parallelism",
            "2",
        ]
    )
    assert called["params"] == (5, 64, 2)
    assert out == "OK"


def test_cli_verify_nope(_pepper):
    backend = qs_kdf.LocalBackend()
    salt = b"\x05" * 16
    qs_kdf.hash_password("pw", salt, backend=backend)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), pytest.raises(SystemExit) as excinfo:
        raise SystemExit(
            cli_module.main(
                [
                    "verify",
                    "pw",
                    "--salt",
                    "05" * 16,
                    "--digest",
                    "00" * 32,
                ]
            )
        )
    assert buf.getvalue().strip() == "NOPE"
    assert excinfo.value.code == 1


def test_braket_backend(monkeypatch):
    class FakeCircuit:
        def h(self, *args, **kwargs):
            return self

        def measure(self, *args, **kwargs):
            return self

    class FakeResult:
        def __init__(self, bits: str, shots: int) -> None:
            self.measurement_counts = {bits: shots}

    class FakeTask:
        def __init__(self, bits: str, shots: int) -> None:
            self._bits = bits
            self._shots = shots

        def result(self):
            return FakeResult(self._bits, self._shots)

    class FakeDevice:
        def __init__(self, bits: str) -> None:
            self.bits = bits
            self.run_shots: list[int] = []

        def run(self, circuit, shots: int):
            self.run_shots.append(shots)
            return FakeTask(self.bits, shots)

    monkeypatch.setitem(
        sys.modules,
        "braket.circuits",
        types.SimpleNamespace(Circuit=lambda: FakeCircuit()),
    )
    monkeypatch.setitem(
        sys.modules,
        "botocore.exceptions",
        types.SimpleNamespace(NoCredentialsError=Exception),
    )

    device1 = FakeDevice("01000010")
    backend = qs_kdf.BraketBackend(device=device1)
    result = backend.run(b"seed")
    assert result == b"\x42" * 10
    assert device1.run_shots == [10]

    device2 = FakeDevice("01000010")
    backend2 = qs_kdf.BraketBackend(device=device2, num_bytes=2)
    result2 = backend2.run(b"seed")
    assert result2 == b"\x42\x42"
    assert device2.run_shots == [2]


def test_braket_backend_device_arn(monkeypatch):
    class FakeCircuit:
        def h(self, *args, **kwargs):
            return self

        def measure(self, *args, **kwargs):
            return self

    class FakeResult:
        def __init__(self, bits: str, shots: int) -> None:
            self.measurement_counts = {bits: shots}

    class FakeTask:
        def __init__(self, bits: str, shots: int) -> None:
            self._bits = bits
            self._shots = shots

        def result(self):
            return FakeResult(self._bits, self._shots)

    class FakeDevice:
        def __init__(self, bits: str) -> None:
            self.bits = bits
            self.run_shots: list[int] = []

        def run(self, circuit, shots: int):
            self.run_shots.append(shots)
            return FakeTask(self.bits, shots)

    captured: dict[str, str] = {}

    def fake_aws_device(arn: str) -> FakeDevice:
        captured["arn"] = arn
        return FakeDevice("01000010")

    monkeypatch.setitem(
        sys.modules,
        "braket.circuits",
        types.SimpleNamespace(Circuit=lambda: FakeCircuit()),
    )
    monkeypatch.setitem(
        sys.modules,
        "braket.aws",
        types.SimpleNamespace(AwsDevice=fake_aws_device),
    )
    monkeypatch.setitem(
        sys.modules,
        "botocore.exceptions",
        types.SimpleNamespace(NoCredentialsError=Exception),
    )

    backend = qs_kdf.BraketBackend(device=None, device_arn="arn:custom")
    result = backend.run(b"seed")
    assert result == b"\x42" * 10
    assert captured["arn"] == "arn:custom"


def test_braket_backend_count_mismatch(monkeypatch):
    class FakeCircuit:
        def h(self, *args, **kwargs):
            return self

        def measure(self, *args, **kwargs):
            return self

    class FakeResult:
        def __init__(self, bits: str, shots: int) -> None:
            self.measurement_counts = {bits: shots - 1}

    class FakeTask:
        def __init__(self, bits: str, shots: int) -> None:
            self._bits = bits
            self._shots = shots

        def result(self):
            return FakeResult(self._bits, self._shots)

    class FakeDevice:
        def __init__(self, bits: str) -> None:
            self.bits = bits

        def run(self, circuit, shots: int):
            return FakeTask(self.bits, shots)

    monkeypatch.setitem(
        sys.modules,
        "braket.circuits",
        types.SimpleNamespace(Circuit=lambda: FakeCircuit()),
    )
    backend = qs_kdf.BraketBackend(device=FakeDevice("00"))
    with pytest.raises(RuntimeError):
        backend.run(b"seed")


def test_braket_backend_unavailable(monkeypatch):
    class FailingDevice:
        def __init__(self, *args, **kwargs) -> None:
            raise Exception("unavailable")

    monkeypatch.setitem(
        sys.modules,
        "braket.aws",
        types.SimpleNamespace(AwsDevice=FailingDevice),
    )
    monkeypatch.setitem(
        sys.modules,
        "botocore.exceptions",
        types.SimpleNamespace(NoCredentialsError=Exception),
    )

    backend = qs_kdf.BraketBackend(device=None)
    with pytest.raises(RuntimeError):
        backend.run(b"seed")


def test_braket_backend_missing_sdk(monkeypatch):
    monkeypatch.delitem(sys.modules, "braket.aws", raising=False)
    monkeypatch.setitem(
        sys.modules,
        "botocore.exceptions",
        types.SimpleNamespace(NoCredentialsError=Exception),
    )

    backend = qs_kdf.BraketBackend(device=None)
    assert backend.device is None
    assert isinstance(backend._init_error, ImportError)
    with pytest.raises(RuntimeError):
        backend.run(b"seed")


def test_braket_backend_missing_credentials(monkeypatch):
    class NoCredsError(Exception):
        pass

    def failing_device(_arn: str):
        raise NoCredsError("no creds")

    monkeypatch.setitem(
        sys.modules,
        "braket.aws",
        types.SimpleNamespace(AwsDevice=failing_device),
    )
    monkeypatch.setitem(
        sys.modules,
        "botocore.exceptions",
        types.SimpleNamespace(NoCredentialsError=NoCredsError),
    )

    backend = qs_kdf.BraketBackend(device=None)
    assert backend.device is None
    assert isinstance(backend._init_error, NoCredsError)
    with pytest.raises(RuntimeError):
        backend.run(b"seed")


def test_braket_backend_missing_circuit(monkeypatch):
    pkg = types.ModuleType("braket")
    pkg.__path__ = []
    monkeypatch.setitem(sys.modules, "braket", pkg)
    sys.modules.pop("braket.circuits", None)
    backend = qs_kdf.BraketBackend(device=object())
    with pytest.raises(RuntimeError):
        backend.run(b"seed")


def test_cli_invalid_salt(_pepper):
    with pytest.raises(argparse.ArgumentTypeError):
        cli_module.main(["hash", "pw", "--salt", "zz"])


def test_cli_invalid_digest(_pepper):
    with pytest.raises(argparse.ArgumentTypeError):
        cli_module.main(["verify", "pw", "--salt", "01" * 16, "--digest", "zz"])


@pytest.mark.parametrize("missing", ["KMS_KEY_ID", "PEPPER_CIPHERTEXT", "REDIS_HOST"])
def test_cli_cloud_missing_env(monkeypatch, missing):
    monkeypatch.setenv("KMS_KEY_ID", "k")
    monkeypatch.setenv("PEPPER_CIPHERTEXT", "c")
    monkeypatch.setenv("REDIS_HOST", "r")
    monkeypatch.delenv(missing)
    with pytest.raises(SystemExit):
        cli_module.main(["hash", "pw", "--salt", "01" * 16, "--cloud"])


@pytest.mark.parametrize("value", [0, -1, 1.5, "x"])
def test_braket_backend_invalid_num_bytes(value):
    with pytest.raises(ValueError):
        qs_kdf.BraketBackend(device=object(), num_bytes=value)


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--time-cost", "0"),
        ("--time-cost", "11"),
        ("--memory-cost", "31"),
        ("--memory-cost", str(1024 * 1024 + 1)),
        ("--parallelism", "0"),
        ("--parallelism", "9"),
    ],
)
def test_cli_param_limits_invalid(flag: str, value: str):
    with pytest.raises(SystemExit):
        cli_module.main(["hash", "pw", "--salt", "01" * 16, flag, value])


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--time-cost", "1"),
        ("--time-cost", "10"),
        ("--memory-cost", "32"),
        ("--memory-cost", str(1024 * 1024)),
        ("--parallelism", "1"),
        ("--parallelism", "8"),
    ],
)
def test_cli_param_limits_valid(flag: str, value: str):
    out = _run_cli(["hash", "pw", "--salt", "01" * 16, flag, value])
    assert out
