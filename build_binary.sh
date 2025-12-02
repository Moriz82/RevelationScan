#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

VENV_DIR=".build-venv"
DIST_DIR="dist"
SPEC_FILE="RevelationScan.spec"

rm -rf "$VENV_DIR" "$SPEC_FILE"
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"
pip install --upgrade pip pyinstaller

pyinstaller \
  --clean \
  --onefile \
  --name RevelationScan \
  "$PROJECT_DIR/src/RevelationScan/__main__.py"

mkdir -p "$DIST_DIR"
cp "dist/RevelationScan" "$DIST_DIR/RevelationScan"

deactivate
rm -rf build "$VENV_DIR" "$SPEC_FILE" dist/__pycache__

echo "Revelation Scan ELF available at $DIST_DIR/RevelationScan"
