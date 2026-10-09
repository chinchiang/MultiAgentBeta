#!/bin/sh
# Linux/WSL2 counterpart of setup.ps1: a hash-checked Python environment and the built console.
#   VIBEAUDIT_PYTHON   the interpreter to create .venv with (default: python3; 3.12 or newer)
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"
base_python="${VIBEAUDIT_PYTHON:-python3}"
"$base_python" -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12 or newer is required"'
"$base_python" -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock.txt
(cd frontend && npm ci && npm run build)
printf '%s\n' 'Setup complete. Run scripts/start-local.sh and open the printed http://127.0.0.1:8000/#token=... URL'
