#!/bin/sh
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"
python_executable="${VIBEAUDIT_PYTHON:-$project_root/.venv/bin/python}"
export PYTHONPATH="$project_root/backend"
"$python_executable" -m pip check
"$python_executable" -m pytest tests -q --junitxml=docs/linux-regression.xml
