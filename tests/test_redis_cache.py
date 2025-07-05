from qs_kdf.core import RedisCache


class MockRedisClient:
    def __init__(self, preset=None):
        self.store = dict(preset or {})
        self.get_calls = []
        self.setex_calls = []

    def get(self, key):
        self.get_calls.append(key)
        return self.store.get(key)

    def setex(self, key, ttl, value):
        self.setex_calls.append((key, ttl, value))
        self.store[key] = value


def test_cache_miss_stores_value_and_calls_producer():
    client = MockRedisClient()
    cache = RedisCache(client)

    produced = {}

    def producer():
        produced["called"] = True
        return b"result"

    result = cache.get_or_set("key", 5, producer)

    assert result == b"result"
    assert produced.get("called") is True
    assert client.get_calls == ["key"]
    assert client.setex_calls == [("key", 5, b"result")]


def test_cache_hit_returns_cached_value():
    client = MockRedisClient({"key": b"cached"})
    cache = RedisCache(client)

    def producer():
        raise AssertionError("producer should not be called")

    result = cache.get_or_set("key", 5, producer)

    assert result == b"cached"
    assert client.get_calls == ["key"]
    assert client.setex_calls == []
