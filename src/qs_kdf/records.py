"""Versioned Argon2id + HMAC password records. See docs/KDF.md for the format."""

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Protocol

from argon2.low_level import Type, hash_secret_raw

MAX_PASSWORD_BYTES = 1024
MAX_RECORD_BYTES = 512
DOMAIN = b"qs-kdf:password-record:v2\x00"
KEY_ID = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
RECORD = re.compile(
    r"\$qs\$2\$argon2id\$v=19\$m=([1-9][0-9]{0,6}),"
    r"t=([1-9][0-9]?),p=([1-9][0-9]?)\$kid=([A-Za-z0-9_-]{1,32})"
    r"\$([A-Za-z0-9+/]{43})\$([A-Za-z0-9+/]{43})\Z"
)


class InvalidRecord(ValueError):
    """Malformed, unsupported, or over-budget stored record."""


class UnknownKey(ValueError):
    """The record's key is not in the application's trusted keyring."""


class ProviderUnavailable(RuntimeError):
    """Protected key service failed; never treat this as a password mismatch."""


class MacProvider(Protocol):
    def has_key(self, key_id: str) -> bool: ...

    def mac(self, key_id: str, message: bytes) -> bytes: ...


class LocalPepper:
    """An immutable snapshot of a server-side keyring, kept outside the user DB."""

    def __init__(self, keys: Mapping[str, bytes]):
        if not keys or any(
            not isinstance(k, str)
            or not KEY_ID.fullmatch(k)
            or not isinstance(v, bytes)
            or len(v) != 32
            for k, v in keys.items()
        ):
            raise ValueError("keyring requires valid IDs and 32-byte keys")
        self._keys = MappingProxyType(dict(keys))

    def has_key(self, key_id: str) -> bool:
        return key_id in self._keys

    def mac(self, key_id: str, message: bytes) -> bytes:
        try:
            key = self._keys[key_id]
        except KeyError as exc:
            raise UnknownKey("password record key unavailable") from exc
        return hmac.digest(key, message, "sha256")


@dataclass(frozen=True)
class Parameters:
    """Memory in KiB. Default is RFC 9106's memory-constrained profile."""

    memory_cost: int = 65_536
    time_cost: int = 3
    parallelism: int = 4

    def __post_init__(self):
        for value, low, high in (
            (self.memory_cost, 19_456, 262_144),
            (self.time_cost, 2, 6),
            (self.parallelism, 1, 8),
        ):
            if type(value) is not int or not low <= value <= high:
                raise ValueError("Argon2 parameters outside supported resource limits")


@dataclass(frozen=True)
class VerificationLimits:
    """Per-call ceilings; applications must additionally limit concurrency."""

    memory_cost: int = 65_536
    time_cost: int = 3
    parallelism: int = 4

    def __post_init__(self):
        Parameters(self.memory_cost, self.time_cost, self.parallelism)

    def check(self, params: Parameters):
        if (
            params.memory_cost > self.memory_cost
            or params.time_cost > self.time_cost
            or params.parallelism > self.parallelism
        ):
            raise InvalidRecord("record exceeds configured verification budget")


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    decoded = base64.b64decode(value + "=", validate=True)
    if len(decoded) != 32 or _encode(decoded) != value:
        raise InvalidRecord("non-canonical record encoding")
    return decoded


def password_bytes(password: str) -> bytes:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    # Check before encoding to bound the allocation for untrusted strings.
    if len(password) > MAX_PASSWORD_BYTES:
        raise ValueError("password exceeds 1024 UTF-8 bytes")
    data = password.encode("utf-8")
    if not data or len(data) > MAX_PASSWORD_BYTES:
        raise ValueError("password must contain 1..1024 UTF-8 bytes")
    return data


@dataclass(frozen=True, repr=False)
class PasswordRecord:
    parameters: Parameters
    key_id: str
    salt: bytes
    tag: bytes

    @property
    def header(self) -> str:
        p = self.parameters
        return (
            f"$qs$2$argon2id$v=19$m={p.memory_cost},t={p.time_cost},"
            f"p={p.parallelism}$kid={self.key_id}${_encode(self.salt)}"
        )

    def encode(self) -> str:
        return self.header + "$" + _encode(self.tag)

    @classmethod
    def parse(cls, encoded: str, limits: VerificationLimits):
        if not isinstance(encoded, str) or len(encoded) > MAX_RECORD_BYTES:
            raise InvalidRecord("invalid password record")
        match = RECORD.fullmatch(encoded)
        if match is None:
            raise InvalidRecord("invalid or unsupported password record")
        m, t, p, key_id, salt, tag = match.groups()
        try:
            params = Parameters(int(m), int(t), int(p))
        except ValueError as exc:
            raise InvalidRecord("unsupported Argon2 parameters") from exc
        limits.check(params)
        return cls(params, key_id, _decode(salt), _decode(tag))


class PasswordHasher:
    """Enroll, verify, and detect records needing password-on-login migration."""

    def __init__(
        self,
        provider: MacProvider,
        current_key_id: str,
        parameters: Parameters | None = None,
        limits: VerificationLimits | None = None,
    ):
        parameters = parameters if parameters is not None else Parameters()
        limits = limits if limits is not None else VerificationLimits()
        if not isinstance(current_key_id, str) or not KEY_ID.fullmatch(current_key_id):
            raise ValueError("invalid current key ID")
        if not provider.has_key(current_key_id):
            raise UnknownKey("current password key unavailable")
        limits.check(parameters)
        self.provider = provider
        self.current_key_id = current_key_id
        self.parameters = parameters
        self.limits = limits

    def _tag(self, password: bytes, record: PasswordRecord) -> bytes:
        if not self.provider.has_key(record.key_id):
            raise UnknownKey("password record key unavailable")
        p = record.parameters
        raw = hash_secret_raw(
            password,
            record.salt,
            time_cost=p.time_cost,
            memory_cost=p.memory_cost,
            parallelism=p.parallelism,
            hash_len=32,
            type=Type.ID,
            version=19,
        )
        # Authenticate every format field as well as the unpersisted Argon2 result.
        message = DOMAIN + record.header.encode("ascii") + b"\x00" + raw
        tag = self.provider.mac(record.key_id, message)
        if not isinstance(tag, bytes) or len(tag) != 32:
            raise ProviderUnavailable("MAC provider returned an invalid result")
        return tag

    def hash(self, password: str, *, supplemental_entropy: bytes = b"") -> str:
        data = password_bytes(password)
        if (
            not isinstance(supplemental_entropy, bytes)
            or len(supplemental_entropy) > 4096
        ):
            raise ValueError("supplemental entropy must be at most 4096 bytes")
        # OS randomness is mandatory even with an untrusted or broken QPU source.
        salt = hashlib.sha256(
            b"qs-kdf:salt:v2\x00" + secrets.token_bytes(32) + supplemental_entropy
        ).digest()
        record = PasswordRecord(self.parameters, self.current_key_id, salt, b"")
        tag = self._tag(data, record)
        return PasswordRecord(self.parameters, self.current_key_id, salt, tag).encode()

    def verify(self, password: str, encoded: str) -> bool:
        record = PasswordRecord.parse(encoded, self.limits)
        return secrets.compare_digest(
            self._tag(password_bytes(password), record), record.tag
        )

    def needs_rehash(self, encoded: str) -> bool:
        record = PasswordRecord.parse(encoded, self.limits)
        if not self.provider.has_key(record.key_id):
            raise UnknownKey("password record key unavailable")
        return (
            record.key_id != self.current_key_id or record.parameters != self.parameters
        )
