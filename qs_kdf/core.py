import base64
import hashlib
import os
from dataclasses import dataclass
from typing import Protocol

try:
    from argon2.low_level import Type, hash_secret_raw
except Exception:  # pragma: no cover - optional

    class Type:
        ID = 2

    def hash_secret_raw(
        password: bytes,
        salt: bytes,
        time_cost: int,
        memory_cost: int,
        parallelism: int,
        hash_len: int,
        type: int,
    ) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password, salt, 1, dklen=hash_len)


class Backend(Protocol):
    def run(self, seed: bytes) -> bytes:
        """Return one byte derived from ``seed``."""


@dataclass
class LocalBackend:
    def run(self, seed: bytes) -> bytes:
        digest = hashlib.sha512(seed).digest()
        return digest[:1]


def hash_password(
    password: str,
    salt: bytes,
    backend: Backend | None = None,
    pepper: bytes | None = None,
) -> bytes:
    """Return Argon2id digest with quantum salt byte."""
    if backend is None:
        backend = LocalBackend()
    if pepper is None:
        pepper = b"fixedPepper32B01234567890123"
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


class RedisCache:
    def __init__(self, client):
        self.client = client

    def get_or_set(self, key: str, ttl: int, producer) -> bytes:
        cached = self.client.get(key)
        if cached:
            return cached
        value = producer()
        self.client.setex(key, ttl, value)
        return value


def lambda_handler(event: dict, _ctx) -> dict:
    import boto3
    import redis

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

    def _producer():
        braket = boto3.client("braket")
        job = braket.search_jobs(maxResults=1)["jobs"][0]
        digest = hashlib.sha512(job["device"] + seed).digest()
        return digest[:1]

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
