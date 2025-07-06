import os
os.environ.setdefault("QS_PEPPER", "x" * 32)

import importlib


import qs_kdf.core as core


def test_warm_up_env(monkeypatch):
    monkeypatch.setenv("QS_WARMUP", "1")
    importlib.reload(core)
    assert core._warmed_up is True
    monkeypatch.delenv("QS_WARMUP")
    importlib.reload(core)


def test_warm_up_function():
    importlib.reload(core)
    assert core._warmed_up is False
    core.warm_up()
    assert core._warmed_up is True
