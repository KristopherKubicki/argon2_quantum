import io
import json
import os
import subprocess
import sys

import pytest

from qs_kdf.cli import main
from qs_kdf import LocalPepper, PasswordHasher, Parameters


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setenv("QS_PEPPER_HEX", "ab" * 32)
    monkeypatch.setenv("QS_CURRENT_KEY_ID", "local-1")


def test_cli_roundtrip(key, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("a passphrase\n"))
    assert main(["hash", "--password-stdin"]) == 0
    record = capsys.readouterr().out.strip()
    monkeypatch.setattr(sys, "stdin", io.StringIO("a passphrase\n"))
    assert main(["verify", "--password-stdin", "--record", record]) == 0
    assert capsys.readouterr().out.strip() == "OK"
    monkeypatch.setattr(sys, "stdin", io.StringIO("wrong\n"))
    assert main(["verify", "--password-stdin", "--record", record]) == 1
    assert capsys.readouterr().out.strip() == "NOPE"


def test_help_and_version_without_secret():
    env = {k: v for k, v in os.environ.items() if not k.startswith("QS_")}
    for option in ("--help", "--version"):
        result = subprocess.run(
            [sys.executable, "-m", "qs_kdf", option],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr


def test_cli_no_traceback_for_invalid_record(key, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("secret-password\n"))
    with pytest.raises(SystemExit) as exc:
        main(["verify", "--password-stdin", "--record", "$bad"])
    assert exc.value.code == 2
    error = capsys.readouterr().err
    assert "Traceback" not in error
    assert "secret-password" not in error


def test_cli_keyring_rotation(tmp_path, monkeypatch, capsys):
    old = PasswordHasher(
        LocalPepper({"old": b"a" * 32}), "old", Parameters(19456, 2, 1)
    )
    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps(
            {
                "current": "new",
                "keys": {"old": (b"a" * 32).hex(), "new": (b"b" * 32).hex()},
            }
        )
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO("pw\n"))
    assert (
        main(
            [
                "verify",
                "--password-stdin",
                "--keyring",
                str(path),
                "--record",
                old.hash("pw"),
            ]
        )
        == 0
    )
    assert capsys.readouterr().out.strip() == "OK"


def test_cli_migrates_only_after_legacy_verification(key, monkeypatch, capsys):
    from qs_kdf.core import hash_password

    salt = b"s" * 16
    digest = hash_password("pw", salt, time_cost=1, memory_cost=32, parallelism=1).hex()
    args = [
        "migrate-legacy",
        "--password-stdin",
        "--salt",
        salt.hex(),
        "--digest",
        digest,
        "--time-cost",
        "1",
        "--memory-cost",
        "32",
        "--parallelism",
        "1",
    ]
    monkeypatch.setattr(sys, "stdin", io.StringIO("bad\n"))
    assert main(args) == 1
    assert capsys.readouterr().out.strip() == "NOPE"
    monkeypatch.setattr(sys, "stdin", io.StringIO("pw\n"))
    assert main(args) == 0
    record = capsys.readouterr().out.strip()
    assert PasswordHasher(
        LocalPepper({"local-1": bytes.fromhex("ab" * 32)}), "local-1"
    ).verify("pw", record)


def test_missing_secret(monkeypatch):
    monkeypatch.delenv("QS_PEPPER_HEX", raising=False)
    with pytest.raises(SystemExit) as exc:
        main(["hash", "--password-stdin"])
    assert exc.value.code == 2
