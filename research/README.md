# Quantum Annoying

**Make guessing repeat expensive work. Then look for every way to reuse it.**

This lab investigates the original speedbump ambition through a password-based
key-exchange model. It is not another password hash and does not use quantum
randomness as a substitute for computational hardness.

**Insecure research simulator. Never use it for passwords or deployment.**
The group has only a 29-bit order, randomness comes from a public seed, and the
ideal ciphers are shared simulator tables. There is no network service. The
production `qs_kdf` package does not import or distribute this lab.

## Run it

From the repository root, with Python 3.10+:

```bash
python -m research.quantum_annoying --guesses 32 --seed 20260921
```

Open [results/index.html](results/index.html) locally for the interactive report.
The experiment needs only the Python standard library. The test suite also uses
pytest and Node.js to check the report's actual JavaScript calculations.

```bash
python -m pip install -e '.[dev]'
pytest -q tests/test_quantum_annoying.py
```

The default report is committed and checked byte-for-byte by tests. Changing
the seed or dictionary size changes the experiment, not a security parameter.
All dictionaries and identities are synthetic; no real password input is offered.

## What the experiment establishes

For seed `20260921`, the correct password is last in a 32-entry dictionary:

| Attacker view / control | Guesses | Distinct discrete-log targets |
| --- | ---: | ---: |
| Public client value X | 32 | 1 |
| Hidden client value X | 32 | 32 |
| Hidden X, wrapping key disclosed | 32 | 1 |
| Server registration record stolen | 32 | 0 |
| Password-checking envelope MAC added | 32 | 0 |

These are results for implemented attacks, **not minimum costs for every attack**.
The solver is classical baby-step giant-step, with shared setup and answer caching.
It actually recovers logarithms; it neither runs Shor nor estimates quantum time.

The hidden-X case demonstrates the intended mechanism: each password candidate
produces a candidate wrapping key, which reveals a candidate group element. In
this attack, checking that guess requires solving that element's logarithm.
Publishing X or disclosing its wrapping key permits one solution to serve all
guesses. A password-checking MAC permits checking guesses directly; this control
models that failure property, not an implementation of authenticated encryption.

Server-record theft is a separate failure boundary. The simulated registration
record exposes values against which decrypted password candidates can be checked
classically. This experiment therefore does not establish a quantum speedbump
for stolen password databases. The production Argon2/protected-key work addresses
a different threat model.

## Reuse across sessions

An alternate implemented attack solves the public server value Y once per
session, and each candidate static value B once per registration/password pair.
It then computes the confirmation key using the server-side algebra. Candidate
B values persist when sessions reuse the same registration envelope.

In the default experiment, two sessions and 64 total guesses require 34 distinct
targets: 33 in the first session and one additional target in the second. In
general this strategy can use roughly N + S targets for N repeated candidates
across S sessions, rather than N times S, absent collisions. This is a directly
reproduced algebraic observation, not a claim of a new cryptanalytic discovery
or a contradiction of a fresh-session security theorem.

## Construction and sources

The honest exchange follows the algebra of Figure 1 in
[Tiepelt, Eaton, Stebila: Quantum Annoying-KHAPE (2023/1513)](https://eprint.iacr.org/2023/1513),
using the revision dated October 27, 2025. It hides the client's ephemeral public
value with a registration key recovered from the password envelope. The public-X
control is an ablation of this model, not a complete implementation of another
published protocol. Registration is an assumed trusted setup step; transport,
enrollment, key storage and concurrent sessions are not implemented here.

The term and adversary distinction come from
[Eaton and Stebila: The “quantum annoying” property of password-authenticated key exchange protocols (2021/696)](https://eprint.iacr.org/2021/696).
Quantum-annoying does not mean fully post-quantum secure. A classical attacker
with a discrete-log capability is a restricted model, not arbitrary coherent
quantum access to every part of the protocol.

[Hhan, Yamakawa, Yun: Quantum Complexity for Discrete Logarithms and Related Problems (2307.03065)](https://arxiv.org/abs/2307.03065)
also motivates taking batching seriously. Theorem 4.5 gives a generic-group
multi-log algorithm with asymptotic operation count O(m log|G| / log m), under
stated conditions including m = Ω(log|G|) and log m / log|G| = o(1).
The report's slider illustrates the m/log2(m) shape with unit constants and
a nominal 256-bit group. It is not a finite-size resource estimate, implementation
of that algorithm, security lower bound, or conversion to quantum seconds.

## Model boundaries

- Ideal-cipher decryption always yields a plausible typed candidate. Replacing
  this with a conventional format or an authentication tag can introduce cheap
  password rejection. No concrete cipher instantiation is supplied.
- SHA-256 and HMAC implement the toy transcript hashes and confirmations. Their
  presence does not instantiate the paper's idealized proof assumptions.
- The simulator owns all lazy tables. Attack functions use the modeled query
  interfaces; inspecting simulator memory or its public seed breaks this toy.
- Identities and session identifiers are bound into confirmation derivation.
  Tests exercise substitution and tampering, not a complete active-adversary proof.
- Distinct-target counts can fall through repeated guesses, collisions, static
  state reuse, or better attacks. They are not counts of independent quantum runs.
- No claim is made about side channels, forward secrecy under all compromise
  patterns, malicious enrollment, denial of service, or production interoperability.

## Gates before deployment could be considered

1. **Specify the claim.** Define transcript capture, server compromise, active
   sessions, ideal-function access, and multi-user/multi-session targets explicitly.
   Decide whether passive-transcript protection is a useful product requirement.
2. **Break the model further.** Add chosen-message and malicious-session attacks,
   cross-user reuse experiments, and a reviewed correspondence to the published
   security game. Document which compromise combinations remove the speedbump.
3. **Instantiate the missing cryptography.** Select a reviewed concrete method
   for the ideal-cipher domains and analyze wrong-password distinguishers. A
   larger group or swapping in AES-GCM alone does not complete this step.
4. **Estimate adversarial resources.** Include multi-target algorithms, memory,
   circuit depth, error correction, and amortization. Produce bounded estimates
   with assumptions before assigning any “quantum cost per guess.”
5. **Obtain independent cryptographic review.** Only then design protocol APIs,
   interoperability vectors, constant-time implementation, enrollment and recovery,
   operational limits, and a deployment trial.

Passing this lab's tests completes a reproducible experiment. It does not complete
these deployment gates. The immediate research deliverable is a falsifiable
mechanism, measured attack traces, and explicit counterexamples to broad claims.
