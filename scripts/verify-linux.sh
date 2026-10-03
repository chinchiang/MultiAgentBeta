#!/bin/sh
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"
python_executable="${VIBEAUDIT_PYTHON:-$project_root/.venv/bin/python}"
export PYTHONPATH="$project_root/backend"
"$python_executable" -m pip check
# A JUnit receipt is written only where VIBEAUDIT_JUNIT_XML points, never silently into docs/.
if [ -n "${VIBEAUDIT_JUNIT_XML:-}" ]; then
  "$python_executable" -m pytest tests -q -rs --junitxml="$VIBEAUDIT_JUNIT_XML"
else
  "$python_executable" -m pytest tests -q -rs
fi
# Like verify.ps1: the committed UI must build from the committed sources.
if [ -d frontend/node_modules ]; then
  (cd frontend && npm run typecheck && npm run build)
else
  printf '%s\n' 'frontend/node_modules missing: run npm ci in frontend to type-check and rebuild the UI; the manifest check below still compares frontend/dist.' >&2
fi
"$python_executable" scripts/package-release.py --check
