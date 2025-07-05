"""Compatibility wrappers for qs_kdf."""

from qs_kdf.core import qstretch, hash_password
from qs_kdf.cli import main

__all__ = ["qstretch", "hash_password", "main"]
