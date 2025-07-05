#!/usr/bin/env bash
set -euo pipefail

# Configure runtimes
export CODEX_ENV_PYTHON_VERSION="3.12"
export CODEX_ENV_NODE_VERSION="20"
source /opt/codex/setup_universal.sh

uv venv venv
source venv/bin/activate

UV_ARGS="--no-index --find-links=/opt/wheels"

uv pip install ${UV_ARGS} -r requirements.txt
uv pip install ${UV_ARGS} -r infra/requirements.txt
uv pip install ${UV_ARGS} -e .
uv pip install ${UV_ARGS} pre-commit

# Install the AWS CDK CLI for infrastructure checks
npm install -g aws-cdk >/dev/null 2>&1 || true

pre-commit install
