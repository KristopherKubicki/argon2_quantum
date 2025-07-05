import random

__all__ = ["TestBackend"]
__test__ = False


class TestBackend:
    """Deterministic backend for testing."""

    def __init__(self, seed: int = 42):
        """Initialize RNG with ``seed``.

        Args:
            seed: Seed for deterministic randomness.
        """

        self.random = random.Random(seed)  # nosec B311 - deterministic helper

    def run(self, seed_bytes: bytes) -> bytes:
        """Return one deterministic byte derived from ``seed_bytes``.

        Args:
            seed_bytes: Seed material for the PRNG.

        Returns:
            bytes: One random byte.
        """

        self.random.seed(int.from_bytes(seed_bytes[:4], "big"))
        return self.random.randbytes(1)
