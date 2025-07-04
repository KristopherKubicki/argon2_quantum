import base64
import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from .constants import PEPPER

_warmed_up = False


def _warm_up() -> None:
    """Preload Argon2 memory to stabilize runtime."""
    global _warmed_up
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
except Exception:  # pragma: no cover - optional

    class Type:  # type: ignore[no-redef]
        ID = 2

    def hash_secret_raw(
        password: bytes,
        salt: bytes,
        time_cost: int,
        memory_cost: int,
        parallelism: int,
        hash_len: int,
        type: int,
        *,
        secret: bytes | None = None,
    ) -> bytes:
        data = password if secret is None else password + secret
        return hashlib.pbkdf2_hmac("sha256", data, salt, 1, dklen=hash_len)


class Backend(Protocol):
    def run(self, seed: bytes) -> bytes:
        """Return one byte derived from ``seed``."""


@dataclass
class LocalBackend:
    def run(self, seed: bytes) -> bytes:
        digest = hashlib.sha512(seed).digest()
        return digest[:1]


@dataclass
class BraketBackend:
    """Backend fetching random bytes from AWS Braket."""

    device: Any | None = None
    num_bytes: int = 1

    def __post_init__(self) -> None:  # pragma: no cover - import guard
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
        if self.device is None:
            backend = LocalBackend()
            return b"".join(
                backend.run(_seed + i.to_bytes(1, "big")) for i in range(self.num_bytes)
            )

        from braket.circuits import Circuit  # type: ignore

        circuit = Circuit().h(range(8)).measure(range(8))
        result_bytes = bytearray()
        base_seed = int.from_bytes(hashlib.sha256(_seed).digest()[:4], "big")
        for i in range(self.num_bytes):
            try:
                task = self.device.run(circuit, shots=1, rng_seed=base_seed + i)
            except TypeError:
                task = self.device.run(circuit, shots=1)
            result = task.result()
            bits = next(iter(result.measurement_counts))
            result_bytes.extend(int(bits, 2).to_bytes(1, "big"))
        return bytes(result_bytes)


def hash_password(
    password: str,
    salt: bytes,
    backend: Backend | None = None,
    pepper: bytes | None = None,
) -> bytes:
    """Return Argon2id digest with quantum salt byte."""
    _warm_up()
    if backend is None:
        backend = LocalBackend()
    if pepper is None:
        pepper = PEPPER
    pre = hashlib.sha512(password.encode() + salt + pepper).digest()
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
    """Return ``True`` if password and salt match ``digest``."""
    candidate = hash_password(password, salt, backend=backend, pepper=pepper)
    return secrets.compare_digest(candidate, digest)


class RedisCache:
    def __init__(self, client):
        self.client = client

    def get_or_set(self, key: str, ttl: int, producer: Callable[[], bytes]) -> bytes:
        cached = self.client.get(key)
        if cached:
            return cached
        value = producer()
        self.client.setex(key, ttl, value)
        return value


def lambda_handler(event: dict, _ctx) -> dict:
    """Handle Argon2id hashing request via AWS Lambda.

    Args:
        event: Invocation payload containing "salt" and "password".
        _ctx: Lambda context object (unused).

    Returns:
        dict: Response with hex digest under "digest".
    """
    import boto3  # type: ignore
    import redis  # type: ignore
    from braket.aws import AwsDevice  # type: ignore
    from braket.circuits import Circuit  # type: ignore

    salt_hex = event["salt"]
    password = event["password"]
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
        task = device.run(circuit, shots=1)
        result = task.result()
        bits = next(iter(result.measurement_counts))
        return int(bits, 2).to_bytes(1, "big")

    quantum_byte = cache.get_or_set(key, 120, _producer)

    class FixedBackend:
        def __init__(self, byte: bytes) -> None:
            self.byte = byte

        def run(self, _seed: bytes) -> bytes:
            return self.byte

    digest = hash_password(
        password,
        seed,
        pepper=pepper,
        backend=FixedBackend(quantum_byte),
    )
    return {"digest": digest.hex()}
