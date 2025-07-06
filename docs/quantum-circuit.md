# Quantum Circuit

This document explains the tiny circuit used by `BraketBackend` to
produce random bytes. The implementation relies on a simple pattern of
Hadamard gates followed by measurements.

## Overview

1. **Initialization** – The circuit allocates eight qubits starting in
the |0⟩ ground state.
2. **Superposition** – A Hadamard gate `H` is applied to each qubit.
   This transforms |0⟩ into 1/√2(|0⟩ + |1⟩), yielding a uniform
   probability of measuring 0 or 1.
3. **Measurement** – All qubits are measured in the computational
   basis. Each shot returns eight classical bits.
4. **Byte assembly** – The backend requests `num_bytes` shots. Each
   result is converted from binary to an integer between 0 and 255 and
   appended to a byte array.

The procedure uses real hardware when available. Errors during
initialization leave the backend in a disabled state, raising a
`RuntimeError` on first use.

## Why this works

Measuring a qubit prepared with a Hadamard gate yields 0 or 1 with equal
probability. Repeating the circuit provides a stream of unbiased random
bits. Grouping eight bits forms a single byte. The simple structure
avoids entanglement and keeps device execution time minimal while still
leveraging quantum randomness.

For development or offline operation, the library ships with a
`LocalBackend` that deterministically hashes the stretched password to
produce the same number of bytes. This makes tests reproducible without
AWS access.
