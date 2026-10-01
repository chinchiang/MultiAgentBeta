#!/bin/sh
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"
python_executable="${VIBEAUDIT_PYTHON:-$project_root/.venv/bin/python}"
if [ ! -x "$python_executable" ]; then
  printf '%s\n' 'Create .venv or set VIBEAUDIT_PYTHON to the prepared environment.' >&2
  exit 1
fi
export PYTHONPATH="$project_root/backend"
exec "$python_executable" -m vibe_audit --port "${1:-8000}"
