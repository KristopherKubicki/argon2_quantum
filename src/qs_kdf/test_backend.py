import hashlib

__all__ = ["TestBackend"]
__test__ = False


class TestBackend:
    def __init__(self, seed: int = 42):
        self._seed = seed.to_bytes(4, "big")

    def run(self, seed_bytes: bytes) -> bytes:
        """Return deterministic bytes for testing."""

        data = self._seed + seed_bytes[:4]
        return hashlib.sha512(data).digest()[:1]
