# Quantum Stretch KDF Overview

The quantum step adds a single byte from AWS Braket to the Argon2 salt. This
increases the offline cracking cost by forcing attackers to replicate the
service call for each guess. It is not a post‑quantum scheme—once large
fault-tolerant QPUs exist the advantage disappears.

A two-hash migration stores both the classical digest and the quantum-extended
version. The extra step can later be removed without requiring all users to
reset their passwords.
