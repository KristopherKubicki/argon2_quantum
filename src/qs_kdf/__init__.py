"""Quantum stretch KDF package."""

from pathlib import Path

import tomllib

_pyproject = Path(__file__).resolve().parent.parent.parent / "pyproject.toml"
with _pyproject.open("rb") as f:
    __version__ = tomllib.load(f)["project"]["version"]

from .core import (
    BraketBackend,
    LocalBackend,
    hash_password,
    lambda_handler,
    qstretch,
    verify_password,
)
from .cli import main as cli
from .test_backend import TestBackend

__all__ = [
    "lambda_handler",
    "cli",
    "TestBackend",
    "qstretch",
    "hash_password",
    "verify_password",
    "LocalBackend",
    "BraketBackend",
    "__version__",
]
