#!/bin/bash
# Prepare a Claude Code cloud session so pytest, the manifest check and the frontend typecheck run.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

root="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$root"

# Python: pinned, hash-checked dependencies in the gitignored .venv (scripts/start-local.sh uses the same path).
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
fi
lock_stamp=.venv/.requirements.lock.sha256
lock_hash=$(sha256sum requirements.lock.txt | cut -d' ' -f1)
if [ "$(cat "$lock_stamp" 2>/dev/null || true)" != "$lock_hash" ]; then
  .venv/bin/python -m pip install --quiet --disable-pip-version-check --require-hashes -r requirements.lock.txt
  printf '%s' "$lock_hash" > "$lock_stamp"
fi

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
