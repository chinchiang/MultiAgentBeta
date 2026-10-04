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
# Like verify.ps1: the SSR/API contract smoke runs against a real backend on loopback.
if command -v node >/dev/null 2>&1 && [ -d frontend/node_modules ]; then
  smoke_port="${VIBEAUDIT_SMOKE_PORT:-8002}"
  smoke_token=$("$python_executable" -c 'import secrets;print(secrets.token_hex(32))')
  smoke_log=$(mktemp)
  smoke_cleaned=''
  smoke_cleanup() {
    [ -n "$smoke_cleaned" ] && return
    smoke_cleaned=1
    kill "$smoke_pid" 2>/dev/null || true
    wait "$smoke_pid" 2>/dev/null || true
    rm -f "$smoke_log"
  }
  trap smoke_cleanup EXIT
  VIBEAUDIT_SESSION_TOKEN="$smoke_token" "$python_executable" -m vibe_audit --port "$smoke_port" >"$smoke_log" 2>&1 &
  smoke_pid=$!
  smoke_ready=''
  i=0
  while [ "$i" -lt 40 ]; do
    if "$python_executable" -c 'import socket,sys; s=socket.socket(); s.settimeout(1); sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)' "$smoke_port"; then
      smoke_ready=1
      break
    fi
    kill -0 "$smoke_pid" 2>/dev/null || break
    i=$((i + 1))
    sleep 0.5
  done
  if [ -n "$smoke_ready" ]; then
    VIBEAUDIT_SESSION_TOKEN="$smoke_token" node frontend/scripts/contract-smoke.mjs --base-url "http://127.0.0.1:$smoke_port"
  else
    cat "$smoke_log" >&2
    printf 'Backend did not open port %s for the SSR/API contract smoke.\n' "$smoke_port" >&2
    exit 1
  fi
  smoke_cleanup
else
  printf '%s\n' 'node or frontend/node_modules missing: the SSR/API contract smoke was skipped; run npm ci in frontend to include it.' >&2
fi
"$python_executable" scripts/package-release.py --check
