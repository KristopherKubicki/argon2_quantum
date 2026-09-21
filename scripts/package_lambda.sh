#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$PROJECT_ROOT/build/lambda"
# This is a generated directory beneath the project, never a caller-supplied path.
rm -rf "$OUT"
mkdir -p "$OUT"
python -m pip install --quiet --require-hashes --only-binary=:all: \
  --platform manylinux_2_28_x86_64 --platform manylinux2014_x86_64 \
  --implementation cp --python-version 3.12 --abi cp312 \
  --target "$OUT" -r "$PROJECT_ROOT/requirements-lambda.txt"
python -m build --wheel --outdir "$PROJECT_ROOT/dist" "$PROJECT_ROOT"
python -m pip install --quiet --no-deps --target "$OUT" \
  "$PROJECT_ROOT/dist/argon2_quantum-0.2.0-py3-none-any.whl"
python - "$OUT" <<'PY'
from pathlib import Path
import shutil
import sys
path = Path(sys.argv[1])
shutil.make_archive(str(path.parent / "lambda"), "zip", path)
PY
