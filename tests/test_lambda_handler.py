import base64
import hashlib
import sys
import types

import pytest

from qs_kdf.core import hash_password, lambda_handler


class DummyBackend:
    def __init__(self, byte: bytes) -> None:
        self.byte = byte

    def run(self, _seed: bytes) -> bytes:
        return self.byte


class FakeKMS:
    def __init__(self, pepper: bytes, cipher: bytes) -> None:
        self.pepper = pepper
        self.cipher = cipher
        self.decrypt_called = 0

    def decrypt(self, KeyId: str, CiphertextBlob: bytes):
        self.decrypt_called += 1
        assert CiphertextBlob == self.cipher
        return {"Plaintext": self.pepper}


class FakeResult:
    def __init__(self, bits: str) -> None:
        self.measurement_counts = {bits: 1}


class FakeTask:
    def __init__(self, bits: str) -> None:
        self._bits = bits

    def result(self):
        return FakeResult(self._bits)


class FakeBraketDevice:
    def __init__(self, bits: str) -> None:
        self.bits = bits
        self.run_calls = 0

    def run(self, circuit, shots: int):
        self.run_calls += 1
        assert shots == 1
        return FakeTask(self.bits)


class FakeCircuit:
    def h(self, *args, **kwargs):
        return self

    def measure(self, *args, **kwargs):
        return self


class FakeBoto3:
    def __init__(self, kms: FakeKMS) -> None:
        self.kms = kms

    def client(self, service: str):
        assert service == "kms"
        return self.kms


class FakeRedisClient:
    def __init__(self, preset: dict[str, bytes] | None = None) -> None:
        self.store: dict[str, bytes] = preset or {}
        self.set_calls: list[tuple[str, int, bytes]] = []

    def get(self, key: str):
        return self.store.get(key)

    def setex(self, key: str, ttl: int, value: bytes):
        self.store[key] = value
        self.set_calls.append((key, ttl, value))


class FakeRedisModule:
    def __init__(self, client: FakeRedisClient) -> None:
        self._client = client

    def Redis(self, host: str, port: int):
        assert host == "r"
        return self._client


@pytest.fixture()
def _env(monkeypatch):
    monkeypatch.delenv("PEPPER", raising=False)
    monkeypatch.setenv("KMS_KEY_ID", "my-key")
    monkeypatch.setenv("PEPPER_CIPHERTEXT", base64.b64encode(b"cipher").decode())
    monkeypatch.setenv("REDIS_HOST", "r")
    monkeypatch.setenv("REDIS_PORT", "6379")


def _expected_digest(
    password: str, salt_hex: str, pepper: bytes, quantum: bytes
) -> str:
    backend = DummyBackend(quantum)
    digest = hash_password(
        password, bytes.fromhex(salt_hex), backend=backend, pepper=pepper
    )
    return digest.hex()


def _setup_modules(
    monkeypatch, kms: FakeKMS, redis_client: FakeRedisClient, device: FakeBraketDevice
) -> None:
    monkeypatch.setitem(sys.modules, "boto3", FakeBoto3(kms))
    monkeypatch.setitem(sys.modules, "redis", FakeRedisModule(redis_client))

    monkeypatch.setitem(
        sys.modules,
        "braket.aws",
        types.SimpleNamespace(AwsDevice=lambda arn: device),
    )
    monkeypatch.setitem(
        sys.modules,
        "braket.circuits",
        types.SimpleNamespace(Circuit=lambda: FakeCircuit()),
    )


def test_lambda_handler_cache_miss(monkeypatch, _env):
    quantum = b"\xaa"
    pepper = b"pepper"
    kms = FakeKMS(pepper, b"cipher")
    device = FakeBraketDevice("10101010")
    redis_client = FakeRedisClient()
    _setup_modules(monkeypatch, kms, redis_client, device)

    event = {"password": "pw", "salt": "00" * 16}
    result = lambda_handler(event, None)

    assert result["digest"] == _expected_digest("pw", event["salt"], pepper, quantum)
    assert kms.decrypt_called == 1
    assert device.run_calls == 1
    assert redis_client.set_calls


def test_lambda_handler_cache_hit(monkeypatch, _env):
    quantum = b"\x42"
    pepper = b"pepper"
    key = hashlib.sha256(bytes.fromhex("11" * 16)).hexdigest()
    redis_client = FakeRedisClient({key: quantum})
    kms = FakeKMS(pepper, b"cipher")
    device = FakeBraketDevice("01000010")
    _setup_modules(monkeypatch, kms, redis_client, device)

    event = {"password": "pw", "salt": "11" * 16}
    result = lambda_handler(event, None)

    assert result["digest"] == _expected_digest("pw", event["salt"], pepper, quantum)
    assert device.run_calls == 0
    assert not redis_client.set_calls


@pytest.mark.parametrize("var", ["KMS_KEY_ID", "PEPPER_CIPHERTEXT", "REDIS_HOST"])
def test_lambda_handler_missing_env(monkeypatch, var, _env):
    redis_client = FakeRedisClient()
    kms = FakeKMS(b"pepper", b"cipher")
    device = FakeBraketDevice("00000000")
    _setup_modules(monkeypatch, kms, redis_client, device)

    monkeypatch.delenv(var, raising=False)
    with pytest.raises(KeyError):
        lambda_handler({"password": "pw", "salt": "22" * 16}, None)
