#!/usr/bin/env bash
set -euo pipefail

# Configure runtimes
export CODEX_ENV_PYTHON_VERSION="3.12"
export CODEX_ENV_NODE_VERSION="20"
source /opt/codex/setup_universal.sh

python -m venv venv
source venv/bin/activate

PIP_ARGS="--no-index --find-links=/opt/wheels"

pip install ${PIP_ARGS} -r requirements.txt
pip install ${PIP_ARGS} -r infra/requirements.txt
pip install ${PIP_ARGS} -e .
pip install ${PIP_ARGS} pre-commit

pre-commit install
