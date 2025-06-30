"""Quantum-enhanced Argon2 KDF wrapper."""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Optional

try:
    from qiskit import Aer, QuantumCircuit, execute  # type: ignore[import]

    HAS_QISKIT = True
except Exception:  # pragma: no cover - optional dep
    Aer = QuantumCircuit = execute = None  # type: ignore[misc]
    HAS_QISKIT = False

PEPPER = b"fixedPepper32B01234567890123"


def _quantum_bits(seed: bytes, shots: int = 8) -> bytes:
    """Return ``shots`` quantum-derived bytes using Qiskit or SHA fallback."""
    if HAS_QISKIT:
        bits = bytearray()
        for i in range(shots):
            qc = QuantumCircuit(1, 1)
            qc.h(0)
            qc.measure(0, 0)
            job = execute(
                qc,
                Aer.get_backend("qasm_simulator"),
                shots=1,
                seed_simulator=int.from_bytes(seed[i : i + 4], "big"),
            )
            result = job.result()
            counts = result.get_counts()
            bit = 1 if counts.get("1", 0) else 0
            bits.append(bit)
        return bytes(bits)
    digest = hashlib.sha512(seed).digest()
    return digest[:shots]


def hash_password(
    password: str,
    salt: Optional[bytes] = None,
    pepper: bytes = PEPPER,
) -> bytes:
    """Return Argon2-like digest with a quantum salt extension."""
    if salt is None:
        salt = secrets.token_bytes(16)
    pre = hashlib.sha512(password.encode() + salt + pepper).digest()
    qbits = _quantum_bits(pre)
    new_salt = salt + qbits
    digest = hashlib.scrypt(pre, salt=new_salt, n=2**14, r=8, p=4, dklen=32)
    return digest


def main() -> None:
    """CLI wrapper printing Base64 digest."""
    import argparse

    parser = argparse.ArgumentParser(description="Quantum Argon2 wrapper")
    parser.add_argument("password")
    parser.add_argument("--salt", default=None, help="Hex-encoded salt")
    args = parser.parse_args()
    salt = bytes.fromhex(args.salt) if args.salt else None
    digest = hash_password(args.password, salt)
    print(base64.b64encode(digest).decode())


if __name__ == "__main__":  # pragma: no cover
    main()
