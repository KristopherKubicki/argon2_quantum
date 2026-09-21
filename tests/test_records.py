import base64
import hmac
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from argon2.low_level import Type, hash_secret_raw

from qs_kdf import (
    InvalidRecord,
    LocalPepper,
    Parameters,
    PasswordHasher,
    PasswordRecord,
    ProviderUnavailable,
    UnknownKey,
    VerificationLimits,
)
import qs_kdf.records as records

KEY = bytes(range(32))
FAST = Parameters(19_456, 2, 1)


@pytest.fixture
def hasher():
    return PasswordHasher(LocalPepper({"k1": KEY}), "k1", parameters=FAST)


def test_round_trip_persists_all_verification_state(hasher):
    encoded = hasher.hash("a long passphrase 🔐", supplemental_entropy=b"QPU bytes")
    fresh = PasswordHasher(LocalPepper({"k1": KEY}), "k1", parameters=FAST)
    assert fresh.verify("a long passphrase 🔐", encoded)
    assert not fresh.verify("wrong", encoded)
    assert encoded != hasher.hash("a long passphrase 🔐")
    assert not fresh.needs_rehash(encoded)


def test_pepper_is_effective_even_when_salt_is_fixed(hasher, monkeypatch):
    monkeypatch.setattr(records.secrets, "token_bytes", lambda n: b"s" * n)
    encoded = hasher.hash("pw")
    other = PasswordHasher(LocalPepper({"k1": b"z" * 32}), "k1", parameters=FAST)
    assert not other.verify("pw", encoded)
    assert encoded != other.hash("pw")


def test_record_matches_independent_composition(hasher, monkeypatch):
    # Independently calculate using Argon2 + standard HMAC; detect format drift.
    monkeypatch.setattr(records.secrets, "token_bytes", lambda n: bytes(range(n)))
    encoded = hasher.hash("correct horse battery staple")
    header, actual = encoded.rsplit("$", 1)
    salt = base64.b64decode(header.rsplit("$", 1)[1] + "=")
    raw = hash_secret_raw(
        b"correct horse battery staple",
        salt,
        time_cost=2,
        memory_cost=19456,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
        version=19,
    )
    expected = hmac.digest(
        KEY, b"qs-kdf:password-record:v2\0" + header.encode() + b"\0" + raw, "sha256"
    )
    assert base64.b64decode(actual + "=") == expected
    assert raw not in (salt, expected)


def test_key_rotation_retains_old_records(hasher):
    old = hasher.hash("pw")
    rotated = PasswordHasher(
        LocalPepper({"k1": KEY, "k2": b"n" * 32}), "k2", parameters=FAST
    )
    assert rotated.verify("pw", old)
    assert rotated.needs_rehash(old)
    new = rotated.hash("pw")
    assert not rotated.needs_rehash(new)
    assert rotated.verify("pw", new)
    with pytest.raises(UnknownKey):
        hasher.verify("pw", new)


def test_cost_upgrade(hasher):
    old = hasher.hash("pw")
    upgraded = PasswordHasher(LocalPepper({"k1": KEY}), "k1")
    assert upgraded.verify("pw", old)
    assert upgraded.needs_rehash(old)


@pytest.mark.parametrize("password", ["a" * 1025, "🔐" * 257, "", "\ud800"])
def test_password_rejected_before_work(password, hasher, monkeypatch):
    monkeypatch.setattr(
        records, "hash_secret_raw", lambda *a, **k: pytest.fail("Argon2 ran")
    )
    with pytest.raises(ValueError):
        hasher.hash(password)


def test_password_preserves_unicode_and_whitespace(hasher):
    record = hasher.hash(" e\u0301 \x00")
    assert hasher.verify(" e\u0301 \x00", record)
    assert not hasher.verify(" é \x00", record)
    assert hasher.verify("🔐" * 256, hasher.hash("🔐" * 256))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda x: x.replace("$2$", "$3$"),
        lambda x: x.replace("v=19", "v=16"),
        lambda x: x.replace("argon2id", "argon2i"),
        lambda x: x.replace("m=19456", "m=9999999"),
        lambda x: x.replace("m=19456", "m=262144"),
        lambda x: x.replace("t=2", "t=99"),
        lambda x: x.replace("p=1", "p=8"),
        lambda x: x.replace("m=19456", "m=019456"),
        lambda x: x + "=",
        lambda x: x + "\n",
        lambda x: x + "a" * 1024,
        lambda x: x.replace("kid=k1", "kid=../../key"),
    ],
)
def test_untrusted_record_rejected_before_argon2(hasher, monkeypatch, mutation):
    record = mutation(hasher.hash("pw"))
    monkeypatch.setattr(
        records, "hash_secret_raw", lambda *a, **k: pytest.fail("Argon2 ran")
    )
    with pytest.raises(InvalidRecord):
        hasher.verify("pw", record)


def test_unknown_key_rejected_before_work(hasher, monkeypatch):
    record = hasher.hash("pw").replace("kid=k1", "kid=missing")
    monkeypatch.setattr(
        records, "hash_secret_raw", lambda *a, **k: pytest.fail("Argon2 ran")
    )
    with pytest.raises(UnknownKey):
        hasher.verify("pw", record)


def test_metadata_is_authenticated(hasher):
    record = hasher.hash("pw")
    alias = PasswordHasher(LocalPepper({"k1": KEY, "k2": KEY}), "k2", parameters=FAST)
    assert not alias.verify("pw", record.replace("kid=k1", "kid=k2"))
    assert not hasher.verify("pw", record.replace("t=2", "t=3"))


def test_noncanonical_base64_is_rejected(hasher):
    record = hasher.hash("pw")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = alphabet.index(record[-1])
    changed = record[:-1] + alphabet[last + 1]
    with pytest.raises(InvalidRecord):
        hasher.verify("pw", changed)


def test_provider_failure_is_not_password_mismatch(hasher, monkeypatch):
    record = hasher.hash("pw")
    monkeypatch.setattr(hasher.provider, "mac", lambda *a: b"short")
    with pytest.raises(ProviderUnavailable):
        hasher.verify("pw", record)


def test_concurrent_verification_has_no_shared_rng_state(hasher):
    record = hasher.hash("pw")
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(lambda _: hasher.verify("pw", record), range(8)))


def test_separate_process_without_quantum_or_cache(hasher):
    record = hasher.hash("pw", supplemental_entropy=b"no longer available")
    program = """
import json, sys
from qs_kdf import LocalPepper, PasswordHasher
record = json.loads(sys.stdin.read())
assert PasswordHasher(LocalPepper({"k1": bytes(range(32))}), "k1").verify("pw", record)
"""
    env = {k: v for k, v in os.environ.items() if not k.startswith("QS_")}
    subprocess.run(
        [sys.executable, "-c", program],
        input=json.dumps(record),
        text=True,
        env=env,
        check=True,
        timeout=30,
    )


@pytest.mark.parametrize(
    "keys", [{}, {"bad$id": KEY}, {"k1": b"short"}, {"k1": "x" * 32}]
)
def test_invalid_keyring(keys):
    with pytest.raises(ValueError):
        LocalPepper(keys)


@pytest.mark.parametrize(
    "args", [(True, 2, 1), (19456, 1, 1), (19456, 2, 0), (262145, 3, 4)]
)
def test_invalid_parameters(args):
    with pytest.raises(ValueError):
        Parameters(*args)


def test_parameter_policy_applies_to_enrollment():
    with pytest.raises(InvalidRecord):
        PasswordHasher(LocalPepper({"k1": KEY}), "k1", Parameters(262144, 3, 4))
    with pytest.raises(ValueError):
        VerificationLimits(time_cost=0)


def test_keyring_snapshot_does_not_change_with_callers_dict():
    keys = {"k1": KEY}
    provider = LocalPepper(keys)
    expected = provider.mac("k1", b"message")
    keys["k1"] = b"z" * 32
    assert provider.mac("k1", b"message") == expected


def test_record_parser_rejects_non_strings():
    for value in (None, {}, b"foo", ""):
        with pytest.raises(InvalidRecord):
            PasswordRecord.parse(value, VerificationLimits())


def test_frozen_v2_known_answer(hasher, monkeypatch):
    monkeypatch.setattr(records.secrets, "token_bytes", lambda n: bytes(range(n)))
    expected = (
        "$qs$2$argon2id$v=19$m=19456,t=2,p=1$kid=k1$"
        "z06c5H3Dw4+NUZNCbQL1PwTTGVzdbOIQUzo+lU3r4oE$"
        "C4Dbdvlas5s/jcMR6V2HFPtDenQdKf4sXCPYLiZPzjU"
    )
    assert hasher.hash("correct horse battery staple") == expected
    assert hasher.verify("correct horse battery staple", expected)
