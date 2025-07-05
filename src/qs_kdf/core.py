import base64
import hashlib
import os
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from .constants import PEPPER

_warmed_up = False
_warm_up_lock = threading.Lock()


def _warm_up() -> None:
    """Preload Argon2 memory to stabilize runtime."""
    global _warmed_up
    if _warmed_up:
        return
    with _warm_up_lock:
        if _warmed_up:
            return
        hash_secret_raw(
            b"x",
            b"\x00" * 17,
            time_cost=3,
            memory_cost=262_144,
            parallelism=4,
            hash_len=32,
            type=Type.ID,
        )
        _warmed_up = True


try:
    from argon2.low_level import Type, hash_secret_raw  # type: ignore
except Exception as exc:  # pragma: no cover - enforce dependency
    raise ImportError(
        "argon2-cffi must be installed; run 'pip install argon2-cffi'"
    ) from exc


class Backend(Protocol):
    def run(self, seed: bytes) -> bytes:
        """Return one byte derived from ``seed``."""


@dataclass
class LocalBackend:
    def run(self, seed: bytes) -> bytes:
        """Return first 10 bytes of SHA-512 digest of ``seed``.

        Args:
            seed: Seed material for the digest.

        Returns:
            bytes: Ten-byte digest slice.
        """

        digest = hashlib.sha512(seed).digest()
        return digest[:10]


def qstretch(password: str, salt: bytes, pepper: bytes = PEPPER) -> bytes:
    """Return 256-bit stretched digest using a double hash."""
    data = password.encode() + salt + pepper
    digest = hashlib.sha512(data).digest()
    return hashlib.sha256(digest).digest()


@dataclass
class BraketBackend:
    """Backend fetching random bytes from AWS Braket."""

    device: Any | None = None
    num_bytes: int = 10

    def __post_init__(self) -> None:  # pragma: no cover - import guard
        """Create default ``AwsDevice`` when none is supplied."""

        if self.device is None:
            try:
                from braket.aws import AwsDevice  # type: ignore
            except Exception:  # pragma: no cover - optional
                self.device = None
            else:
                self.device = AwsDevice(
                    "arn:aws:braket:::device/quantum-simulator/amazon/sv1"
                )

    def run(self, _seed: bytes) -> bytes:
        """Return ``num_bytes`` random bytes from Braket or fallback."""

        if self.device is None:
            backend = LocalBackend()
            return b"".join(
                backend.run(_seed + i.to_bytes(1, "big")) for i in range(self.num_bytes)
            )

        from braket.circuits import Circuit  # type: ignore

        circuit = Circuit().h(range(8)).measure(range(8))
        task = self.device.run(circuit, shots=self.num_bytes)
        result = task.result()
        result_bytes = bytearray()
        for bits, count in result.measurement_counts.items():
            result_bytes.extend(int(bits, 2).to_bytes(1, "big") * count)
        return bytes(result_bytes)


def hash_password(
    password: str,
    salt: bytes,
    backend: Backend | None = None,
    pepper: bytes | None = None,
) -> bytes:
    """Compute Argon2id digest with quantum salt bytes.

    Args:
        password: Password string to hash.
        salt: Salt bytes.
        backend: Backend providing quantum randomness.
        pepper: Optional pepper value.

    Returns:
        bytes: Final digest bytes.
    """
    _warm_up()
    if backend is None:
        backend = LocalBackend()
    if pepper is None:
        pepper = PEPPER
    pre = qstretch(password, salt, pepper=pepper)
    quantum = backend.run(pre)
    new_salt = salt + quantum
    digest = hash_secret_raw(
        password.encode(),
        new_salt,
        time_cost=3,
        memory_cost=262_144,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )
    return digest


def verify_password(
    password: str,
    salt: bytes,
    digest: bytes,
    backend: Backend | None = None,
    pepper: bytes | None = None,
) -> bool:
    """Check that password and salt produce ``digest``.

    Args:
        password: Candidate password string.
        salt: Original salt bytes.
        digest: Expected digest bytes.
        backend: Backend providing quantum randomness.
        pepper: Optional pepper value.

    Returns:
        bool: ``True`` on match, ``False`` otherwise.
    """
    candidate = hash_password(password, salt, backend=backend, pepper=pepper)
    return secrets.compare_digest(candidate, digest)


class RedisCache:
    def __init__(self, client):
        """Initialize wrapper around a Redis client.

        Args:
            client: Redis client instance.
        """

        self.client = client

    def get_or_set(self, key: str, ttl: int, producer: Callable[[], bytes]) -> bytes:
        """Get cached value or compute and store it.

        Args:
            key: Cache key.
            ttl: Time-to-live in seconds.
            producer: Callable producing the value.

        Returns:
            bytes: Cached or newly produced value.
        """

        cached = self.client.get(key)
        if cached:
            return cached
        value = producer()
        self.client.setex(key, ttl, value)
        return value


@dataclass
class HashEvent:
    """Invocation payload for :func:`lambda_handler`."""

    password: str
    salt: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HashEvent":
        """Return ``HashEvent`` built from ``data``."""
        if not isinstance(data, Mapping):
            raise TypeError("event must be a mapping")
        try:
            password = data["password"]
            salt = data["salt"]
        except KeyError as exc:  # pragma: no cover - tested indirectly
            raise KeyError(f"missing field: {exc.args[0]}") from exc
        if not isinstance(password, str) or not isinstance(salt, str):
            raise TypeError("password and salt must be strings")
        return cls(password=password, salt=salt)


def lambda_handler(event: Mapping[str, Any] | HashEvent, _ctx) -> dict:
    """Handle Argon2id hashing request via AWS Lambda.

    Args:
        event: Invocation payload containing ``salt`` and ``password``.
        _ctx: Lambda context object (unused).

    Returns:
        dict: Response with hex digest under "digest".
    """
    import boto3  # type: ignore
    import redis  # type: ignore
    from braket.aws import AwsDevice  # type: ignore
    from braket.circuits import Circuit  # type: ignore

    evt = event if isinstance(event, HashEvent) else HashEvent.from_dict(event)
    salt_hex = evt.salt
    password = evt.password
    kms_key = os.environ["KMS_KEY_ID"]
    cipher_b64 = os.environ["PEPPER_CIPHERTEXT"]

    kms = boto3.client("kms")
    pepper = kms.decrypt(KeyId=kms_key, CiphertextBlob=base64.b64decode(cipher_b64))[
        "Plaintext"
    ]

    r = redis.Redis(
        host=os.environ["REDIS_HOST"], port=int(os.environ.get("REDIS_PORT", "6379"))
    )
    cache = RedisCache(r)
    seed = bytes.fromhex(salt_hex)
    key = hashlib.sha256(seed).hexdigest()

    device = AwsDevice("arn:aws:braket:::device/quantum-simulator/amazon/sv1")
    circuit = Circuit().h(range(8)).measure(range(8))

    def _producer():
        result_bytes = bytearray()
        for _ in range(10):
            task = device.run(circuit, shots=1)
            result = task.result()
            bits = next(iter(result.measurement_counts))
            result_bytes.extend(int(bits, 2).to_bytes(1, "big"))
        return bytes(result_bytes)

    quantum_bytes = cache.get_or_set(key, 120, _producer)

    class FixedBackend:
        def __init__(self, byte: bytes) -> None:
            self.byte = byte

        def run(self, _seed: bytes) -> bytes:
            return self.byte

    digest = hash_password(
        password,
        seed,
        pepper=pepper,
        backend=FixedBackend(quantum_bytes),
    )
    return {"digest": digest.hex()}
