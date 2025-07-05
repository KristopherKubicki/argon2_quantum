#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/build/lambda"

rm -rf "$OUT"
mkdir -p "$OUT"

# Install only runtime dependencies

pip install --quiet --target "$OUT" -r "$ROOT/requirements.txt"
cp -r "$ROOT"/src/* "$OUT"/

cd "$OUT" && zip -r ../lambda.zip .
