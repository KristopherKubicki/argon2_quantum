# Packaging the Lambda Function

`scripts/package_lambda.sh` bundles the runtime modules and Python
dependencies into `build/lambda.zip`. This archive is ready for manual
upload to AWS Lambda or for use by deployment tooling.

Run the script whenever you update the runtime dependencies in
`requirements.txt` or change code under `src/`. The script installs the
packages into `build/lambda/`, copies only the `qs_kdf` package and
`qsargon2.py`, and then creates the zip file. Tests and helper scripts are
intentionally omitted from the archive.
