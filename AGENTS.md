# AGENT Instructions

- Always run `pre-commit run --files <files>` for modified files.
- Ensure `pytest` passes.
- The `BraketBackend` in `src/qs_kdf/core.py` must fail with `RuntimeError`
  if AWS Braket is unavailable. Do not use placeholder randomness.
  Initialization should handle missing SDK or credentials gracefully and
  only raise when ``run`` is called.
