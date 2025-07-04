import random

__all__ = ["TestBackend"]
__test__ = False


class TestBackend:
    """Deterministic backend for tests."""

    def __init__(self, seed: int = 42):
        """Initialize random generator with ``seed``."""
        self.random = random.Random(seed)  # nosec B311 - deterministic helper

    def run(self, seed_bytes: bytes) -> bytes:
        """Return pseudo-random byte derived from ``seed_bytes``."""
        self.random.seed(int.from_bytes(seed_bytes[:4], "big"))
        return self.random.randbytes(1)
