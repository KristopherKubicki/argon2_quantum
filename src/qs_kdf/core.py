import base64
import hashlib
import os
import secrets
import threading
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

from .constants import PEPPER

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


try:
    from argon2.low_level import Type, hash_secret_raw  # type: ignore
except Exception as exc:  # pragma: no cover - enforce dependency
    raise ImportError(
        "argon2-cffi must be installed; run 'pip install argon2-cffi'"
    ) from exc

_warm_up()


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
    """Return 256-bit digest from password, salt, and pepper.

    Args:
        password: Password string to stretch.
        salt: Salt bytes used for the first hash.
        pepper: Optional pepper value used in the hash.

    Returns:
        bytes: Final stretched digest.
    """
    data = password.encode() + salt + pepper
    digest = hashlib.sha512(data).digest()
    return hashlib.sha256(digest).digest()


@dataclass
class BraketBackend:
    """Backend fetching random bytes from AWS Braket."""

    device: Any | None = None
    num_bytes: int = 10
    _init_error: Exception | None = field(init=False, default=None)

    def __post_init__(self) -> None:  # pragma: no cover - import guard
        """Create default ``AwsDevice`` when none is supplied.

        Returns:
            None

        Notes:
            ``self.device`` remains ``None`` when the SDK is missing and
            :meth:`run` will raise :class:`RuntimeError`.
        """

        if not isinstance(self.num_bytes, int) or self.num_bytes <= 0:
            raise ValueError("num_bytes must be a positive integer")

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
                self.device = AwsDevice(
                    "arn:aws:braket:::device/qpu/ionq/ionQdevice"
                )
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
        """Return ``HashEvent`` built from ``data``.

        Args:
            data: Mapping with keys ``"password"`` and ``"salt"``.

        Returns:
            HashEvent: Parsed event object.

        Raises:
            KeyError: If a required field is missing.
            TypeError: If ``data`` is not a mapping or values are not strings.
        """
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

    Raises:
        KeyError: If ``event`` is missing required fields.
        TypeError: If ``event`` is not a valid mapping or strings.
    """
    import boto3  # type: ignore
    import redis  # type: ignore
    from braket.aws import AwsDevice  # type: ignore

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

    device = AwsDevice("arn:aws:braket:::device/qpu/ionq/ionQdevice")
    backend = BraketBackend(device=device)

    def _producer() -> bytes:
        return backend.run(seed)

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
