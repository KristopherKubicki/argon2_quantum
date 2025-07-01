import base64
import hashlib
import types
from unittest import mock

import qs_kdf.core as core
import pytest
import sys


class FakeRedis:
    def __init__(self, data=None):
        self.data = data or {}
        self.get_calls = 0
        self.setex_calls = []

    def get(self, key):
        self.get_calls += 1
        return self.data.get(key)

    def setex(self, key, ttl, value):
        self.setex_calls.append((key, ttl, value))
        self.data[key] = value


def setup_boto3(monkeypatch, pepper=b"pepper", device=b"dev"):
    kms_client = mock.Mock()
    kms_client.decrypt.return_value = {"Plaintext": pepper}
    braket_client = mock.Mock()
    braket_client.search_jobs.return_value = {"jobs": [{"device": device}]}

    def client(name):
        return {"kms": kms_client, "braket": braket_client}[name]

    boto3_mod = types.SimpleNamespace(client=client)
    monkeypatch.setitem(sys.modules, "boto3", boto3_mod)
    return kms_client, braket_client


def setup_redis(monkeypatch, redis_obj):
    redis_mod = types.SimpleNamespace(Redis=lambda **kwargs: redis_obj)
    monkeypatch.setitem(sys.modules, "redis", redis_mod)


class DummyBackend:
    def __init__(self, byte):
        self.byte = byte

    def run(self, _seed):
        return self.byte


def expected_digest(password, seed, quantum_byte, pepper):
    return core.hash_password(password, seed, pepper=pepper, backend=DummyBackend(quantum_byte)).hex()


def test_lambda_handler_cache_miss(monkeypatch):
    seed_hex = "00" * 16
    event = {"salt": seed_hex, "password": "pw"}
    pepper = b"pepper"
    device = b"dev"

    monkeypatch.setenv("KMS_KEY_ID", "key")
    monkeypatch.setenv("PEPPER_CIPHERTEXT", base64.b64encode(pepper).decode())
    monkeypatch.setenv("REDIS_HOST", "host")
    monkeypatch.setenv("REDIS_PORT", "6379")

    redis_obj = FakeRedis()
    setup_redis(monkeypatch, redis_obj)
    kms, braket = setup_boto3(monkeypatch, pepper, device)

    seed = bytes.fromhex(seed_hex)
    quantum_byte = hashlib.sha512(device + seed).digest()[:1]
    result = core.lambda_handler(event, None)

    key = hashlib.sha256(seed).hexdigest()
    assert result["digest"] == expected_digest("pw", seed, quantum_byte, pepper)
    assert redis_obj.get_calls == 1
    assert redis_obj.setex_calls[0][0] == key
    assert kms.decrypt.called
    assert braket.search_jobs.called


def test_lambda_handler_cache_hit(monkeypatch):
    seed_hex = "ff" * 16
    event = {"salt": seed_hex, "password": "pw"}
    pepper = b"pepper"
    device = b"dev"

    monkeypatch.setenv("KMS_KEY_ID", "key")
    monkeypatch.setenv("PEPPER_CIPHERTEXT", base64.b64encode(pepper).decode())
    monkeypatch.setenv("REDIS_HOST", "host")
    monkeypatch.setenv("REDIS_PORT", "6379")

    seed = bytes.fromhex(seed_hex)
    quantum_byte = b"\x01"
    cache = FakeRedis({hashlib.sha256(seed).hexdigest(): quantum_byte})
    setup_redis(monkeypatch, cache)
    kms, braket = setup_boto3(monkeypatch, pepper, device)

    result = core.lambda_handler(event, None)

    assert result["digest"] == expected_digest("pw", seed, quantum_byte, pepper)
    assert braket.search_jobs.call_count == 0


def test_lambda_handler_kms_error(monkeypatch):
    seed_hex = "aa" * 16
    event = {"salt": seed_hex, "password": "pw"}
    monkeypatch.setenv("KMS_KEY_ID", "key")
    monkeypatch.setenv("PEPPER_CIPHERTEXT", base64.b64encode(b"pepper").decode())
    monkeypatch.setenv("REDIS_HOST", "host")
    monkeypatch.setenv("REDIS_PORT", "6379")

    redis_obj = FakeRedis()
    setup_redis(monkeypatch, redis_obj)

    def client(name):
        if name == "kms":
            raise RuntimeError("kms fail")
        return mock.Mock()

    boto3_mod = types.SimpleNamespace(client=client)
    monkeypatch.setitem(sys.modules, "boto3", boto3_mod)

    with pytest.raises(RuntimeError):
        core.lambda_handler(event, None)
