# Lambda artifact

Use `bash scripts/package_lambda.sh` in an activated development environment.
The script installs hash-locked AWS runtime dependencies as Linux x86_64 Python
3.12 wheels, builds the project wheel, and installs it into `build/lambda/`.
Installing the wheel includes distribution metadata, so version discovery works
without the source checkout or `pyproject.toml` at runtime. The script also emits
`build/lambda.zip`.

The artifact excludes the Braket SDK and Redis. Its handler is
`qs_kdf.service.lambda_handler`. On a compatible Linux host, smoke-test from a
directory outside the checkout using the artifact as the sole PYTHONPATH and
without QS_PEPPER. CI does this before synthesizing the stack.

Regenerate the runtime lock deliberately after dependency updates:

```bash
uv pip compile pyproject.toml --extra aws --generate-hashes --python-version 3.12 \
  -o requirements-lambda.txt
pip-audit -r requirements-lambda.txt
```

Review the lock diff, run all tests, rebuild, and rerun the isolated smoke test.
Version changes must also update the explicit wheel filename in the package
script. The generated artifact contains binary extensions: do not build by simply
copying a virtual environment from macOS, Windows, or another architecture.
