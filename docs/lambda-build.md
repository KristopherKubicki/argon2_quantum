# Packaging the Lambda Function

`scripts/package_lambda.sh` bundles the source code and Python dependencies into
`build/lambda.zip`. This archive is ready for manual upload to AWS Lambda or for
use by deployment tooling.

Run the script whenever you update the dependencies in `requirements.txt` or
change code under `src/`. The script installs the packages into
`build/lambda/`, copies the project sources, and creates the zip file.
