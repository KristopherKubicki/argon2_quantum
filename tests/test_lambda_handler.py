import base64
import os
import sys
import types

import qs_kdf.core as core


class FakeKMS:
    def decrypt(self, KeyId, CiphertextBlob):
        assert KeyId == "kms-key"
        assert CiphertextBlob == b"cipher"
        return {"Plaintext": b"pepper!"}

    def generate_random(self, NumberOfBytes):
        assert NumberOfBytes == 1
        return {"Plaintext": b"\x99"}


class FakeRedis:
    def __init__(self, host=None, port=None):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def setex(self, key, ttl, value):
        self.store[key] = value


def test_lambda_handler(monkeypatch):
    fake_boto3 = types.ModuleType("boto3")
    fake_boto3.client = lambda service: FakeKMS()
    fake_redis = types.ModuleType("redis")
    fake_redis.Redis = lambda host=None, port=None: FakeRedis()

    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    monkeypatch.setitem(sys.modules, "redis", fake_redis)

    os.environ["KMS_KEY_ID"] = "kms-key"
    os.environ["PEPPER_CIPHERTEXT"] = base64.b64encode(b"cipher").decode()
    os.environ["REDIS_HOST"] = "localhost"

    event = {"salt": "01" * 16, "password": "pw"}
    result = core.lambda_handler(event, None)
    assert result == {
        "digest": "f03ed03bfde85534ba1bada2a209aea884289325fdf795102720ad938ced897d"
    }
