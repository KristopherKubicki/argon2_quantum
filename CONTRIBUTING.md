# Contributing

This project requires **Python 3.10 or newer**. The CI tests run on
Python 3.10 through 3.14. Development can begin quickly with the
`.codex/setup.sh` script or by installing the requirements manually.

## Quick Setup

Run the bundled setup script from the repository root. It creates a
virtual environment, installs the dependencies with `uv` and configures
`pre-commit`:

```bash
./.codex/setup.sh
```

## Manual Setup

If the script cannot be used, create a virtual environment yourself and
install the dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
uv pip install -r requirements.txt
uv pip install -r requirements-dev.txt
uv pip install -e .
pre-commit install
```

## Running Checks

Before committing, run the style hooks only on the files you changed and
execute the test suite:

```bash
pre-commit run --files <files>
pytest
```


The v2 protocol lives in `src/qs_kdf/records.py`; legacy code in `core.py` is
retained for migration. Do not silently change an existing record format, key ID,
or legacy derivation. Add a version and a migration plan for protocol changes.
See `docs/security/design-review.md` for the threat model and release limits.
