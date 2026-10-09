#!/bin/sh
# Starts a real backend on loopback and runs the console's SSR/API contract smoke against it
# (frontend/scripts/contract-smoke.mjs). Used by scripts/verify-linux.sh and the backend CI job.
#   VIBEAUDIT_PYTHON       the interpreter with the project installed (default: .venv/bin/python)
#   VIBEAUDIT_SMOKE_PORT   the loopback port the backend listens on (default: 8002)
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"
python_executable="${VIBEAUDIT_PYTHON:-$project_root/.venv/bin/python}"
export PYTHONPATH="$project_root/backend"
command -v node >/dev/null 2>&1 || { printf '%s\n' 'node is required for the SSR/API contract smoke' >&2; exit 1; }
[ -d frontend/node_modules ] || { printf '%s\n' 'frontend/node_modules missing: run npm ci in frontend first' >&2; exit 1; }
smoke_port="${VIBEAUDIT_SMOKE_PORT:-8002}"
smoke_token=$("$python_executable" -c 'import secrets;print(secrets.token_hex(32))')
smoke_log=$(mktemp)
smoke_data=$(mktemp -d)
smoke_pid=''
cleanup() {
  [ -n "$smoke_pid" ] && kill "$smoke_pid" 2>/dev/null || true
  [ -n "$smoke_pid" ] && wait "$smoke_pid" 2>/dev/null || true
  rm -rf "$smoke_log" "$smoke_data"
}
trap cleanup EXIT
# Its own data directory: the smoke must not read or write the operator's runs.
VIBEAUDIT_SESSION_TOKEN="$smoke_token" "$python_executable" -m vibe_audit --port "$smoke_port" --data-dir "$smoke_data/data" >"$smoke_log" 2>&1 &
smoke_pid=$!
i=0
while [ "$i" -lt 40 ]; do
  if "$python_executable" -c 'import socket,sys; s=socket.socket(); s.settimeout(1); sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)' "$smoke_port"; then
    VIBEAUDIT_SESSION_TOKEN="$smoke_token" node frontend/scripts/contract-smoke.mjs --base-url "http://127.0.0.1:$smoke_port"
    exit 0
  fi
  kill -0 "$smoke_pid" 2>/dev/null || break
  i=$((i + 1))
  sleep 0.5
done
cat "$smoke_log" >&2
printf 'Backend did not open port %s for the SSR/API contract smoke.\n' "$smoke_port" >&2
exit 1
