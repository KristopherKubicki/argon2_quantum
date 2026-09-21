"""IAM-authenticated Lambda entry point and non-exportable AWS KMS pepper."""

import json
import os
import re
from functools import lru_cache
from types import MappingProxyType
from typing import Mapping

from .records import (
    KEY_ID,
    PasswordHasher,
    PasswordRecord,
    ProviderUnavailable,
    UnknownKey,
    VerificationLimits,
    password_bytes,
)

KMS_KEY_ARN = re.compile(
    r"arn:aws(?:-us-gov|-cn)?:kms:[a-z0-9-]+:[0-9]{12}:key/"
    r"(?:[a-f0-9-]{36}|mrk-[a-f0-9]{32})\Z"
)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key in keyring")
        result[key] = value
    return result


class KmsMac:
    """Allowlisted immutable key ARNs; caller input never selects an AWS ARN."""

    def __init__(self, client, keys: Mapping[str, str]):
        if (
            not isinstance(keys, Mapping)
            or not 1 <= len(keys) <= 16
            or any(
                not isinstance(k, str)
                or not KEY_ID.fullmatch(k)
                or not isinstance(v, str)
                or not KMS_KEY_ARN.fullmatch(v)
                for k, v in keys.items()
            )
        ):
            raise ValueError("KMS keyring requires valid IDs and immutable key ARNs")
        self._client = client
        self._keys = MappingProxyType(dict(keys))

    def has_key(self, key_id: str) -> bool:
        return key_id in self._keys

    def mac(self, key_id: str, message: bytes) -> bytes:
        if key_id not in self._keys:
            raise UnknownKey("password record key unavailable")
        try:
            response = self._client.generate_mac(
                KeyId=self._keys[key_id], Message=message, MacAlgorithm="HMAC_SHA_256"
            )
            mac = response["Mac"]
            if (
                not isinstance(mac, bytes)
                or len(mac) != 32
                or response.get("KeyId") != self._keys[key_id]
                or response.get("MacAlgorithm") != "HMAC_SHA_256"
            ):
                raise ValueError("invalid KMS result")
            return mac
        except Exception:
            # Do not put the request or SDK exception (possibly sensitive) in logs.
            raise ProviderUnavailable("KMS MAC service unavailable") from None


@lru_cache(maxsize=1)
def _configured_hasher(keyring_json: str, current_key_id: str) -> PasswordHasher:
    import boto3
    from botocore.config import Config

    if not keyring_json or len(keyring_json) > 4096:
        raise RuntimeError("QS_KMS_KEYS must contain the trusted KMS keyring")
    keys = json.loads(keyring_json, object_pairs_hook=_unique_object)
    provider = KmsMac(None, keys)
    hasher = PasswordHasher(provider, current_key_id)
    provider._client = boto3.client(
        "kms",
        config=Config(
            connect_timeout=2,
            read_timeout=3,
            retries={"mode": "standard", "total_max_attempts": 2},
        ),
    )
    return hasher


def lambda_handler(event, _context) -> dict:
    """Private direct-invocation API. Applications persist records themselves.

    No HTTP endpoint, password logging, QPU call, raw digest return, or fallback.
    Caller must handle authorization, account rate limits, and DB integrity.
    """
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    action = event.get("action")
    allowed = (
        {"action", "password"} if action == "hash" else {"action", "password", "record"}
    )
    if (
        not isinstance(action, str)
        or action not in {"hash", "verify"}
        or set(event) != allowed
    ):
        raise ValueError("expected action hash/password or verify/password/record")
    password_bytes(event["password"])
    if action == "verify":
        PasswordRecord.parse(event["record"], VerificationLimits())
    current = os.environ.get("QS_CURRENT_KEY_ID", "")
    hasher = _configured_hasher(os.environ.get("QS_KMS_KEYS", ""), current)
    if action == "hash":
        return {"record": hasher.hash(event["password"])}
    valid = hasher.verify(event["password"], event["record"])
    return {
        "valid": valid,
        "needs_rehash": valid and hasher.needs_rehash(event["record"]),
    }
