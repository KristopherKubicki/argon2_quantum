#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/build/lambda"

# Remove old build output
rm -rf "$OUT"
# Create output directory
mkdir -p "$OUT"

# Install only runtime dependencies
pip install --quiet --target "$OUT" -r "$ROOT/requirements.txt"

# Copy runtime modules into build dir
cp -r "$ROOT/src/qs_kdf" "$OUT"
cp "$ROOT/src/qsargon2.py" "$OUT"

# Package all files into lambda.zip
cd "$OUT" && zip -r ../lambda.zip .
