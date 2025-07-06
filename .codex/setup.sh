#!/usr/bin/env bash
set -euo pipefail

# Configure runtimes
export CODEX_ENV_PYTHON_VERSION="3.12"
export CODEX_ENV_NODE_VERSION="20"
if [ -f /opt/codex/setup_universal.sh ]; then
    # shellcheck disable=SC1091
    source /opt/codex/setup_universal.sh || true
fi

uv venv venv
source venv/bin/activate

UV_ARGS=""
if [ -d /opt/wheels ]; then
    UV_ARGS="--no-index --find-links=/opt/wheels"
fi

uv pip install ${UV_ARGS} -r requirements.txt
uv pip install ${UV_ARGS} -r requirements-dev.txt
uv pip install ${UV_ARGS} -r infra/requirements.txt
uv pip install ${UV_ARGS} -e .
uv pip install ${UV_ARGS} pre-commit || true

if command -v pre-commit >/dev/null 2>&1; then
    pre-commit install
fi
