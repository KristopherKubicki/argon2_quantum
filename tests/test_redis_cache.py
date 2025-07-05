import logging

from qs_kdf.core import RedisCache, RedisError


class GetErrorClient:
    def __init__(self) -> None:
        self.setex_called = False

    def get(self, key: str):
        raise RedisError("boom")

    def setex(self, key: str, ttl: int, value: bytes):
        self.setex_called = True


class SetErrorClient:
    def __init__(self) -> None:
        self.setex_called = False

    def get(self, key: str):
        return None

    def setex(self, key: str, ttl: int, value: bytes):
        self.setex_called = True
        raise RedisError("fail")


def test_get_error(caplog):
    client = GetErrorClient()
    cache = RedisCache(client)
    with caplog.at_level(logging.ERROR):
        result = cache.get_or_set("k", 1, lambda: b"v")
    assert result == b"v"
    assert not client.setex_called
    assert "boom" in caplog.text


def test_set_error(caplog):
    client = SetErrorClient()
    cache = RedisCache(client)
    with caplog.at_level(logging.ERROR):
        result = cache.get_or_set("k", 1, lambda: b"v")
    assert result == b"v"
    assert client.setex_called
    assert "fail" in caplog.text
