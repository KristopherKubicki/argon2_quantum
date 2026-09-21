import hmac

import boto3
from botocore.stub import Stubber
import pytest

from qs_kdf import (
    InvalidRecord,
    LocalPepper,
    PasswordHasher,
    Parameters,
    ProviderUnavailable,
)
from qs_kdf.service import KmsMac, lambda_handler
import qs_kdf.service as service

ARN = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789abc"
KEY = b"x" * 32


class FakeKms:
    def __init__(self):
        self.calls = []

    def generate_mac(self, **kwargs):
        self.calls.append(kwargs)
        assert kwargs["KeyId"] == ARN
        assert kwargs["MacAlgorithm"] == "HMAC_SHA_256"
        return {
            "Mac": hmac.digest(KEY, kwargs["Message"], "sha256"),
            "KeyId": ARN,
            "MacAlgorithm": "HMAC_SHA_256",
        }


@pytest.fixture
def configured(monkeypatch):
    client = FakeKms()
    hasher = PasswordHasher(KmsMac(client, {"k1": ARN}), "k1", Parameters(19456, 2, 1))
    monkeypatch.setattr(service, "_configured_hasher", lambda *args: hasher)
    return client, hasher


def test_lambda_survives_loss_of_all_transient_state(configured, monkeypatch):
    client, hasher = configured
    record = lambda_handler({"action": "hash", "password": "pw"}, None)["record"]
    fresh_client = FakeKms()
    fresh = PasswordHasher(
        KmsMac(fresh_client, {"k1": ARN}), "k1", Parameters(19456, 2, 1)
    )
    monkeypatch.setattr(service, "_configured_hasher", lambda *args: fresh)
    assert lambda_handler(
        {"action": "verify", "password": "pw", "record": record}, None
    ) == {
        "valid": True,
        "needs_rehash": False,
    }
    assert not lambda_handler(
        {"action": "verify", "password": "bad", "record": record}, None
    )["valid"]
    assert len(client.calls) == 1
    assert len(fresh_client.calls) == 2
    # KMS and local HMAC agree on the exact protocol, independently of caching.
    assert PasswordHasher(LocalPepper({"k1": KEY}), "k1").verify("pw", record)


@pytest.mark.parametrize(
    "event",
    [
        None,
        [],
        {},
        {"password": "pw", "salt": "00" * 16},
        {"action": "hash", "password": "pw", "device_arn": "attacker"},
        {"action": "hash", "password": "x" * 1025},
        {"action": "verify", "password": "pw", "record": "$malformed"},
        {"action": "hash", "password": "pw", "memory_cost": 999999},
    ],
)
def test_invalid_input_rejected_before_aws(event, monkeypatch):
    monkeypatch.setattr(
        service, "_configured_hasher", lambda *a: pytest.fail("AWS accessed")
    )
    with pytest.raises((ValueError, TypeError, InvalidRecord)):
        lambda_handler(event, None)


def test_kms_failure_never_falls_back(configured, monkeypatch):
    client, hasher = configured
    record = hasher.hash("pw")

    def unavailable(**kwargs):
        raise RuntimeError("SDK error containing sensitive data")

    monkeypatch.setattr(client, "generate_mac", unavailable)
    with pytest.raises(ProviderUnavailable) as caught:
        lambda_handler({"action": "verify", "password": "pw", "record": record}, None)
    assert "sensitive" not in str(caught.value)


def test_real_sdk_request_contract():
    client = boto3.client(
        "kms",
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )
    with Stubber(client) as stub:
        stub.add_response(
            "generate_mac",
            {
                "Mac": b"m" * 32,
                "KeyId": ARN,
                "MacAlgorithm": "HMAC_SHA_256",
            },
            {"KeyId": ARN, "Message": b"message", "MacAlgorithm": "HMAC_SHA_256"},
        )
        assert KmsMac(client, {"k1": ARN}).mac("k1", b"message") == b"m" * 32
        stub.assert_no_pending_responses()


def test_keyring_rejects_aliases():
    with pytest.raises(ValueError):
        KmsMac(FakeKms(), {"k1": "alias/mutable"})


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"Mac": b"short"},
        {"Mac": b"m" * 32, "KeyId": "wrong", "MacAlgorithm": "HMAC_SHA_256"},
    ],
)
def test_bad_kms_response_is_failure(monkeypatch, response):
    client = FakeKms()
    monkeypatch.setattr(client, "generate_mac", lambda **kwargs: response)
    with pytest.raises(ProviderUnavailable):
        KmsMac(client, {"k1": ARN}).mac("k1", b"message")


def test_configuration_checks_before_client_creation(monkeypatch):
    service._configured_hasher.cache_clear()
    monkeypatch.setattr(boto3, "client", lambda *a, **k: pytest.fail("AWS accessed"))
    for keyring, current in (
        ("", "k1"),
        ('{"k1":"alias/bad"}', "k1"),
        ('{"k1":"a","k1":"b"}', "k1"),
        ("[]", "k1"),
    ):
        with pytest.raises((ValueError, RuntimeError)):
            service._configured_hasher(keyring, current)


def test_configuration_sets_bounded_timeouts_and_caches_client(monkeypatch):
    import json

    service._configured_hasher.cache_clear()
    calls = []

    def client(name, config):
        assert name == "kms"
        assert config.connect_timeout == 2
        assert config.read_timeout == 3
        assert config.retries["total_max_attempts"] == 2
        calls.append(name)
        return FakeKms()

    monkeypatch.setattr(boto3, "client", client)
    config = json.dumps({"k1": ARN})
    first = service._configured_hasher(config, "k1")
    assert service._configured_hasher(config, "k1") is first
    assert len(calls) == 1
    assert first.verify("pw", first.hash("pw"))
    service._configured_hasher.cache_clear()
