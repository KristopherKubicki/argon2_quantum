# Argon2 Quantum / Quantum Annoying

**Experimental research — not production-ready cryptography.**

## Status

The original “quantum speedbump” claim was not supported by the implementation.
Adding quantum-generated randomness to an Argon2 salt does not establish that an
attacker must run a quantum computation or repeat an AWS Braket call for every
password guess. The earlier claims of an added quantum work factor are withdrawn.

The code and older documentation on the default branch are retained as an
experimental prototype. They should not be treated as deployment guidance,
a validated encryption algorithm, or a post-quantum security guarantee.

## Current work

Two separate draft efforts document what is supported and what remains research:

- [Password-record hardening and design review — PR #174](https://github.com/KristopherKubicki/argon2_quantum/pull/174):
  versioned Argon2id records and protected-key access. This is a conventional
  security boundary, not a quantum computational speedbump.
- [Quantum Annoying research lab — PR #175](https://github.com/KristopherKubicki/argon2_quantum/pull/175):
  a reproducible toy key-exchange model, executable attacks, and an interactive
  report exploring password-dependent discrete-log targets. Its results are
  specific attack demonstrations, not quantum timings or a security proof.

The lab also demonstrates limitations: key disclosure, server-record theft,
and reuse across sessions can reduce or remove the intended extra work.
Its small group, public seeded randomness, and simulated ideal ciphers make it
unsuitable for real credentials. A concrete construction, broader analysis,
and independent cryptographic review remain prerequisites to deployment.

See the [research notes and roadmap](https://github.com/KristopherKubicki/argon2_quantum/blob/quantum-annoying-lab/research/README.md)
for the measured results, assumptions, published references, and open questions.
These draft branches have not been merged into the default branch.

## Development

Historical implementation material remains under [src](src/), [docs](docs/),
and [infra](infra/). Existing setup and deployment instructions describe the
prototype; they do not override the status above.

## License

[MIT](LICENSE).
