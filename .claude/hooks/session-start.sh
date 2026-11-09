#!/bin/bash
# Prepare a Claude Code session, local or cloud, so pytest, the manifest check and the frontend typecheck run.
set -euo pipefail

root="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$root"

# Python: the hash-checked .venv, reinstalled only when requirements.lock.txt changes (the rest of the machine's
# environment, PostgreSQL and the scanner runtime, is scripts/dev-env.sh run in full).
sh scripts/dev-env.sh venv

# Frontend: install exactly the lockfile once; later sessions reuse the cached node_modules.
if [ ! -d frontend/node_modules ]; then
  (cd frontend && npm ci --no-audit --no-fund)
fi

if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  {
    echo "export PATH=\"$root/.venv/bin:\$PATH\""
    echo "export PYTHONPATH=\"$root/backend\""
  } >> "$CLAUDE_ENV_FILE"
fi
