import base64
import hashlib
import os
import sys
from types import SimpleNamespace

from qs_kdf.core import hash_password, lambda_handler


class FakeKMS:
    def decrypt(self, KeyId, CiphertextBlob):
        return {"Plaintext": b"pepper"}


class FakeBraket:
    def __init__(self):
        self.calls = 0

    def search_jobs(self, maxResults):
        self.calls += 1
        return {"jobs": [{"device": b"device1"}]}


class FakeRedis:
    def __init__(self):
        self.store = {}
        self.get_calls = 0
        self.setex_calls = 0

    def get(self, key):
        self.get_calls += 1
        return self.store.get(key)

    def setex(self, key, ttl, value):
        self.setex_calls += 1
        self.store[key] = value


def _setup(monkeypatch):
    braket = FakeBraket()
    redis_client = FakeRedis()
    fake_boto3 = SimpleNamespace(
        client=lambda service: FakeKMS() if service == "kms" else braket
    )
    fake_redis = SimpleNamespace(Redis=lambda host=None, port=None: redis_client)
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    monkeypatch.setitem(sys.modules, "redis", fake_redis)
    os.environ.setdefault("KMS_KEY_ID", "k")
    os.environ.setdefault("PEPPER_CIPHERTEXT", base64.b64encode(b"pepper").decode())
    os.environ.setdefault("REDIS_HOST", "localhost")
    os.environ.setdefault("REDIS_PORT", "6379")
    return braket, redis_client


def test_lambda_handler_caching(monkeypatch):
    braket, redis_client = _setup(monkeypatch)
    event = {"password": "pw", "salt": "01" * 16}
    result1 = lambda_handler(event, None)
    result2 = lambda_handler(event, None)
    seed = bytes.fromhex(event["salt"])
    quantum = hashlib.sha512(b"device1" + seed).digest()[:1]

    class FixedBackend:
        def __init__(self, b: bytes):
            self.b = b

        def run(self, _seed: bytes) -> bytes:
            return self.b

    expected = hash_password(
        event["password"], seed, pepper=b"pepper", backend=FixedBackend(quantum)
    )
    assert result1 == {"digest": expected.hex()}
    assert result2 == result1
    assert braket.calls == 1
    assert redis_client.get_calls == 2
    assert redis_client.setex_calls == 1
