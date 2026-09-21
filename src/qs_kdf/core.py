"""Quantum-stretch key derivation and backend interfaces.

This module exposes utility functions to perform Argon2-based key derivation
that optionally incorporates randomness from quantum hardware. Local hashing is
provided by :class:`LocalBackend`, while :class:`BraketBackend` fetches bytes
from AWS Braket devices when available. The exported ``hash_password`` and
``verify_password`` helpers use these backends to combine passwords, salts and
pepper into stable digests.
"""

import hashlib
import os
import secrets
import threading
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from .constants import _load_pepper

_warmed_up = False
_warm_up_lock = threading.Lock()


def _warm_up() -> None:
    """Preload Argon2 memory to stabilize runtime.

    Returns:
        None
    """
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


def warm_up() -> None:
    """Public wrapper enabling explicit warm-up."""

    _warm_up()


try:
    from argon2.low_level import Type, hash_secret_raw  # type: ignore
except Exception as exc:  # pragma: no cover - enforce dependency
    raise ImportError(
        "argon2-cffi must be installed; run 'pip install argon2-cffi'"
    ) from exc

if os.getenv("QS_WARMUP") == "1":
    _warm_up()


class Backend(Protocol):
    def run(self, seed: bytes) -> bytes:
        """Return bytes derived from ``seed``.

        Length of the returned bytes depends on the backend.
        """


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


def qstretch(password: str, salt: bytes, pepper: bytes | None = None) -> bytes:
    """Return 256-bit digest from password, salt, and pepper.

    Args:
        password: Password string to stretch.
        salt: Salt bytes used for the first hash.
        pepper: Optional 32-byte pepper value used in the hash.

    Returns:
        bytes: Final stretched digest.
    """
    if pepper is None:
        pepper = _load_pepper()
    if not isinstance(pepper, (bytes, bytearray)) or len(pepper) == 0:
        raise ValueError("pepper must be non-empty bytes")
    data = password.encode() + salt + pepper
    digest = hashlib.sha512(data).digest()
    return hashlib.sha256(digest).digest()


@dataclass
class BraketBackend:
    """Backend fetching random bytes from AWS Braket."""

    device: Any | None = None
    device_arn: str = ""
    num_bytes: int = 10
    _init_error: Exception | None = field(init=False, default=None)

    def __post_init__(self) -> None:  # pragma: no cover - import guard
        """Create default ``AwsDevice`` when none is supplied.

        Returns:
            None

        Notes:
            ``self.device`` remains ``None`` when the SDK is missing and
            :meth:`run` will raise :class:`RuntimeError`. Set
            ``device_arn`` to select a different quantum device.
        """

        if type(self.num_bytes) is not int or not 1 <= self.num_bytes <= 4096:
            raise ValueError("num_bytes must be an integer between 1 and 4096")

        if self.device is None:
            try:
                from braket.aws import AwsDevice  # type: ignore
                from botocore.exceptions import NoCredentialsError  # type: ignore
            except ImportError as exc:  # pragma: no cover - optional
                logging.getLogger(__name__).error("Braket import failed: %s", exc)
                self._init_error = exc
                self.device = None
                return

            try:
                if not self.device_arn:
                    raise ValueError("an explicit Braket device ARN is required")
                self.device = AwsDevice(self.device_arn)
            except NoCredentialsError as exc:  # pragma: no cover - optional
                logging.getLogger(__name__).error("AWS credentials missing: %s", exc)
                self._init_error = exc
                self.device = None
            except Exception as exc:  # pragma: no cover - optional
                logging.getLogger(__name__).error("AwsDevice init failed: %s", exc)
                self._init_error = exc
                self.device = None

    def run(self, _seed: bytes) -> bytes:
        """Return ``num_bytes`` random bytes from Braket.

        Args:
            _seed: Ignored seed bytes.

        Returns:
            bytes: Random bytes fetched from the device.

        Raises:
            RuntimeError: If ``self.device`` is ``None``.
        """

        if self.device is None:
            msg = "Braket backend unavailable"
            if self._init_error:
                msg += f": {self._init_error}"
            raise RuntimeError(msg)

        try:
            from braket.circuits import Circuit  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional
            raise RuntimeError("Braket backend unavailable") from exc

        try:
            circuit = Circuit().h(range(8)).measure(range(8))
            task = self.device.run(
                circuit, shots=self.num_bytes, poll_timeout_seconds=120
            )
            result = task.result()
            measurements = result.measurements
            if len(measurements) != self.num_bytes:
                raise ValueError("measurement count mismatch")
            result_bytes = bytearray()
            for row in measurements:
                if len(row) != 8 or any(bit not in (0, 1) for bit in row):
                    raise ValueError("invalid measurement bits")
                value = 0
                for bit in row:
                    value = (value << 1) | int(bit)
                result_bytes.append(value)
            return bytes(result_bytes)
        except Exception:
            raise RuntimeError(
                "Braket execution or measurement validation failed"
            ) from None


def hash_password(
    password: str,
    salt: bytes,
    backend: Backend | None = None,
    pepper: bytes | None = None,
    time_cost: int = 3,
    memory_cost: int = 262_144,
    parallelism: int = 4,
) -> bytes:
    """Legacy v0.1 digest. For new records use records.PasswordHasher.

    A nondeterministic backend cannot be verified without its exact saved bytes.

    Args:
        password: Password string to hash.
        salt: Salt bytes.
        backend: Backend providing quantum randomness.
        pepper: Optional pepper value.
        time_cost: Argon2 time cost.
        memory_cost: Argon2 memory cost.
        parallelism: Argon2 parallelism.

    Returns:
        bytes: Final digest bytes.
    """
    if backend is None:
        backend = LocalBackend()
    if pepper is None:
        pepper = _load_pepper()
    pre = qstretch(password, salt, pepper=pepper)
    quantum = backend.run(pre)
    new_salt = salt + quantum
    digest = hash_secret_raw(
        password.encode(),
        new_salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
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
    time_cost: int = 3,
    memory_cost: int = 262_144,
    parallelism: int = 4,
) -> bool:
    """Check that password and salt produce ``digest``.

    Args:
        password: Candidate password string.
        salt: Original salt bytes.
        digest: Expected digest bytes.
        backend: Backend providing quantum randomness.
        pepper: Optional pepper value.
        time_cost: Argon2 time cost.
        memory_cost: Argon2 memory cost.
        parallelism: Argon2 parallelism.

    Returns:
        bool: ``True`` on match, ``False`` otherwise.
    """
    candidate = hash_password(
        password,
        salt,
        backend=backend,
        pepper=pepper,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
    )
    return secrets.compare_digest(candidate, digest)


class RedisCache:
    def __init__(self, client):
        """Initialize wrapper around a Redis client.

        Args:
            client: Redis client instance.

        Returns:
            None
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

        if not isinstance(ttl, int) or ttl <= 0:
            raise ValueError("ttl must be a positive integer")

        cached = self.client.get(key)
        if cached:
            return cached
        value = producer()
        self.client.setex(key, ttl, value)
        return value


def lambda_handler(event, context) -> dict:
    """Compatibility import for the v2 service; legacy cloud hashing is disabled."""
    from .service import lambda_handler as handler

    return handler(event, context)
