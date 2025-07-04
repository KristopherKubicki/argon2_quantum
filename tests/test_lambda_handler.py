import base64
import hashlib
import sys
import time
import types

import qs_kdf


class FakeKMS:
    def __init__(self, byte: bytes, pepper: bytes) -> None:
        self.byte = byte
        self.pepper = pepper
        self.generated = 0

    def decrypt(self, KeyId: str, CiphertextBlob: bytes):
        assert KeyId == "keyid"
        assert CiphertextBlob == self.pepper
        return {"Plaintext": self.pepper}

    def generate_random(self, NumberOfBytes: int):
        self.generated += 1
        assert NumberOfBytes == 1
        return {"Plaintext": self.byte}


def _setup(monkeypatch, store: dict[str, bytes], byte: bytes, pepper: bytes):
    kms = FakeKMS(byte, pepper)
    fake_boto3 = types.SimpleNamespace(client=lambda name: kms)

    class FakeRedis:
        def __init__(self, host: str, port: int) -> None:
            self.host = host
            self.port = port

        def get(self, key: str):
            return store.get(key)

        def setex(self, key: str, _ttl: int, value: bytes) -> None:
            store[key] = value

    fake_redis = types.SimpleNamespace(Redis=FakeRedis)
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    monkeypatch.setitem(sys.modules, "redis", fake_redis)
    monkeypatch.setenv("KMS_KEY_ID", "keyid")
    monkeypatch.setenv("PEPPER_CIPHERTEXT", base64.b64encode(pepper).decode())
    monkeypatch.setenv("REDIS_HOST", "cache")
    monkeypatch.setenv("REDIS_PORT", "6379")
    return kms


def _expected(password: str, salt: bytes, byte: bytes, pepper: bytes) -> bytes:
    class Fixed:
        def __init__(self, b: bytes) -> None:
            self.b = b

        def run(self, _seed: bytes) -> bytes:
            return self.b

    return qs_kdf.hash_password(password, salt, backend=Fixed(byte), pepper=pepper)


def test_lambda_handler_cache_miss(monkeypatch):
    byte = b"\x42"
    pepper = b"pepper"
    store: dict[str, bytes] = {}
    kms = _setup(monkeypatch, store, byte, pepper)
    event = {"salt": "00" * 16, "password": "pw"}
    salt = bytes.fromhex(event["salt"])
    key = hashlib.sha256(salt).hexdigest()
    start = time.perf_counter()
    result = qs_kdf.lambda_handler(event, None)
    duration = time.perf_counter() - start
    assert duration < 0.1
    assert result["digest"] == _expected("pw", salt, byte, pepper).hex()
    assert store[key] == byte
    assert kms.generated == 1


def test_lambda_handler_cache_hit(monkeypatch):
    byte = b"\x24"
    pepper = b"pepper"
    salt = bytes.fromhex("00" * 16)
    key = hashlib.sha256(salt).hexdigest()
    store = {key: byte}
    kms = _setup(monkeypatch, store, byte, pepper)
    event = {"salt": "00" * 16, "password": "pw"}
    start = time.perf_counter()
    result = qs_kdf.lambda_handler(event, None)
    duration = time.perf_counter() - start
    assert duration < 0.1
    assert result["digest"] == _expected("pw", salt, byte, pepper).hex()
    assert kms.generated == 0
