import base64
import sys
import io
import contextlib
import importlib
import hashlib
import qs_kdf

cli_module = importlib.import_module("qs_kdf.cli")


def _run_cli(argv: list[str]) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli_module.main(argv)
    return buf.getvalue().strip()


class DummyRedis:
    def __init__(self):
        self.store = {}

    def get(self, key: str):
        return self.store.get(key)

    def setex(self, key: str, ttl: int, value: bytes) -> None:
        self.store[key] = value


class DummyBoto3:
    class KMS:
        def decrypt(self, KeyId: str, CiphertextBlob: bytes):
            return {"Plaintext": b"pepper"}

    class Braket:
        def search_jobs(self, maxResults: int):
            return {"jobs": [{"device": b"device"}]}

    def client(self, name: str):
        if name == "kms":
            return self.KMS()
        if name == "braket":
            return self.Braket()
        raise AssertionError(name)


class DummyRedisModule:
    def Redis(self, host: str, port: int):
        return DummyRedis()


# Backend class tests

def test_local_backend_run():
    seed = b"seed"
    backend = qs_kdf.LocalBackend()
    expected = hashlib.sha512(seed).digest()[:1]
    assert backend.run(seed) == expected


def test_rediscache_get_or_set():
    cache = qs_kdf.core.RedisCache(DummyRedis())
    value = cache.get_or_set("k", 1, lambda: b"v")
    assert value == b"v"
    value2 = cache.get_or_set("k", 1, lambda: b"x")
    assert value2 == b"v"


# CLI and lambda_handler tests

def test_cli_verify_fail():
    backend = qs_kdf.LocalBackend()
    salt = b"\x05" * 16
    digest = qs_kdf.hash_password("pw", salt, backend=backend)
    out = _run_cli([
        "verify",
        "bad",
        "--salt",
        "05" * 16,
        "--digest",
        digest.hex(),
    ])
    assert out == "NOPE"


def test_lambda_handler(monkeypatch):
    event = {"password": "pw", "salt": "06" * 16}
    monkeypatch.setenv("KMS_KEY_ID", "key")
    monkeypatch.setenv(
        "PEPPER_CIPHERTEXT", base64.b64encode(b"cipher").decode()
    )
    monkeypatch.setenv("REDIS_HOST", "h")
    monkeypatch.setenv("REDIS_PORT", "1")
    monkeypatch.setitem(sys.modules, "boto3", DummyBoto3())
    monkeypatch.setitem(sys.modules, "redis", DummyRedisModule())

    def fake_hash(password: str, salt: bytes, *, pepper: bytes, backend):
        assert pepper == b"pepper"
        quantum = hashlib.sha512(b"device" + salt).digest()[:1]
        assert backend.run(b"x") == quantum
        return b"\x01\x02"

    monkeypatch.setattr(qs_kdf.core, "hash_password", fake_hash)
    out = qs_kdf.lambda_handler(event, None)
    assert out == {"digest": "0102"}
