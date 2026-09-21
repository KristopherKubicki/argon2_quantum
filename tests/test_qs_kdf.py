"""Legacy compatibility and Braket adapter tests; v2 tests live in test_records."""

import hashlib
import sys
import types

import pytest
from argon2.low_level import Type, hash_secret_raw

import qs_kdf
from qs_kdf.constants import _load_pepper
from qs_kdf.legacy import verify_local


def test_legacy_hash_compatibility():
    salt = b"\x09" * 16
    pre = hashlib.sha256(
        hashlib.sha512(b"pw" + salt + _load_pepper()).digest()
    ).digest()
    extra = hashlib.sha512(pre).digest()[:10]
    expected = hash_secret_raw(
        b"pw",
        salt + extra,
        time_cost=3,
        memory_cost=262144,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )
    assert qs_kdf.hash_password("pw", salt) == expected
    assert verify_local("pw", salt.hex(), expected.hex())
    assert not verify_local("wrong", salt.hex(), expected.hex())


def test_original_cloud_pepper_flaw_is_documented():
    class Fixed:
        def run(self, seed):
            return b"q" * 10

    # Legacy behavior preserved only for migration, never used by the v2 service.
    first = qs_kdf.hash_password(
        "pw",
        b"s" * 16,
        backend=Fixed(),
        pepper=b"a" * 32,
        memory_cost=32,
        time_cost=1,
        parallelism=1,
    )
    second = qs_kdf.hash_password(
        "pw",
        b"s" * 16,
        backend=Fixed(),
        pepper=b"b" * 32,
        memory_cost=32,
        time_cost=1,
        parallelism=1,
    )
    assert first == second


def test_original_cloud_randomness_flaw_is_documented():
    class Fresh:
        counter = 0

        def run(self, seed):
            self.counter += 1
            return bytes([self.counter]) * 10

    backend = Fresh()
    options = dict(backend=backend, memory_cost=32, time_cost=1, parallelism=1)
    digest = qs_kdf.hash_password("pw", b"s" * 16, **options)
    assert not qs_kdf.verify_password("pw", b"s" * 16, digest, **options)


class Circuit:
    def h(self, qubits):
        assert list(qubits) == list(range(8))
        return self

    def measure(self, qubits):
        return self


@pytest.fixture
def circuit(monkeypatch):
    monkeypatch.setitem(
        sys.modules, "braket.circuits", types.SimpleNamespace(Circuit=Circuit)
    )


class Device:
    def __init__(self, measurements):
        self.measurements = measurements
        self.calls = []

    def run(self, circuit, **kwargs):
        self.calls.append(kwargs)
        return types.SimpleNamespace(
            result=lambda: types.SimpleNamespace(measurements=self.measurements)
        )


def test_braket_preserves_shot_order(circuit):
    # Repeated shot values must not be regrouped using measurement_counts.
    rows = [[0] * 8, [1] * 8, [0] * 8]
    device = Device(rows)
    backend = qs_kdf.BraketBackend(device=device, num_bytes=3)
    assert backend.run(b"ignored") == b"\x00\xff\x00"
    assert device.calls == [{"shots": 3, "poll_timeout_seconds": 120}]


@pytest.mark.parametrize("rows", [None, [], [[0] * 7], [[2] * 8], [[0] * 8] * 2])
def test_braket_invalid_measurements_fail_closed(circuit, rows):
    with pytest.raises(RuntimeError):
        qs_kdf.BraketBackend(device=Device(rows), num_bytes=1).run(b"")


@pytest.mark.parametrize("value", [True, 0, -1, 1.5, "10", 4097])
def test_braket_bounds(value):
    with pytest.raises(ValueError):
        qs_kdf.BraketBackend(device=object(), num_bytes=value)


def test_braket_missing_sdk_is_deferred(monkeypatch):
    monkeypatch.setitem(sys.modules, "braket.aws", None)
    backend = qs_kdf.BraketBackend(device_arn="arn:explicit")
    assert backend.device is None
    with pytest.raises(RuntimeError):
        backend.run(b"")


def test_braket_missing_credentials_is_deferred(monkeypatch):
    def fail(arn):
        raise RuntimeError("no credentials")

    monkeypatch.setitem(
        sys.modules, "braket.aws", types.SimpleNamespace(AwsDevice=fail)
    )
    backend = qs_kdf.BraketBackend(device_arn="arn:explicit")
    assert backend.device is None
    with pytest.raises(RuntimeError):
        backend.run(b"")


def test_braket_requires_explicit_device(monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "braket.aws",
        types.SimpleNamespace(AwsDevice=lambda _: pytest.fail("device created")),
    )
    backend = qs_kdf.BraketBackend()
    with pytest.raises(RuntimeError):
        backend.run(b"")


@pytest.mark.parametrize(
    "options",
    [
        {"salt_hex": "x" * 65},
        {"digest_hex": "bad"},
        {"time_cost": 0},
        {"memory_cost": 2**32},
        {"parallelism": True},
        {"memory_cost": 32, "parallelism": 8},
    ],
)
def test_legacy_migration_bounds(options):
    args = dict(password="pw", salt_hex="00" * 16, digest_hex="00" * 32)
    args.update(options)
    with pytest.raises(ValueError):
        verify_local(**args)
