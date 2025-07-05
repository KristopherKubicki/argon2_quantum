"""Quantum stretch KDF package."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import re

from .core import (
    BraketBackend,
    LocalBackend,
    warm_up,
    hash_password,
    lambda_handler,
    qstretch,
    verify_password,
)
from .cli import main as cli
from .test_backend import TestBackend

_pyproject = Path(__file__).resolve().parent.parent.parent / "pyproject.toml"


def _read_version(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, flags=re.MULTILINE)
    if not match:
        raise RuntimeError("version not found in pyproject.toml")
    return match.group(1)


try:
    __version__ = version("argon2-quantum")
except PackageNotFoundError:
    __version__ = _read_version(_pyproject)

__all__ = [
    "lambda_handler",
    "cli",
    "TestBackend",
    "qstretch",
    "hash_password",
    "warm_up",
    "verify_password",
    "LocalBackend",
    "BraketBackend",
    "__version__",
]
