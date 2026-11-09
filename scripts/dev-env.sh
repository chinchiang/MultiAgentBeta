#!/bin/sh
# Rebuild this machine's development environment, idempotently; what /tmp loses on a reboot lives elsewhere.
#   scripts/dev-env.sh        .venv, then the PostgreSQL container, the offline OSV database and runtime-static.json
#   scripts/dev-env.sh venv   only .venv (.claude/hooks/session-start.sh runs this at every session start)
#   VIBEAUDIT_PYTHON          the interpreter to create .venv with (default: python3.12, the version CI runs, else python3);
#                             remove .venv to rebuild it with another one
# State outside the repository lives in VIBEAUDIT_DEV_CACHE (default ~/.cache/vibeaudit-dev): pgpass, osv/, workers/
# and runtime-static.json. The container is VIBEAUDIT_DEV_PG (default va-live-pg) on 127.0.0.1:VIBEAUDIT_DEV_PG_PORT
# (default 55433); an existing container is started and given the password in pgpass, never recreated.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

# Python: pinned, hash-checked dependencies in the gitignored .venv (scripts/start-local.sh uses the same path),
# reinstalled only when requirements.lock.txt changes.
if [ ! -x .venv/bin/python ]; then
  base_python="${VIBEAUDIT_PYTHON:-$(command -v python3.12 || command -v python3)}"
  "$base_python" -m venv .venv
fi
lock_stamp=.venv/.requirements.lock.sha256
lock_hash=$(sha256sum requirements.lock.txt | cut -d' ' -f1)
if [ "$(cat "$lock_stamp" 2>/dev/null || true)" != "$lock_hash" ]; then
  .venv/bin/python -m pip install --quiet --disable-pip-version-check --require-hashes -r requirements.lock.txt
  printf '%s' "$lock_hash" > "$lock_stamp"
fi
[ "${1:-}" = "venv" ] && exit 0

cache="${VIBEAUDIT_DEV_CACHE:-$HOME/.cache/vibeaudit-dev}"
container="${VIBEAUDIT_DEV_PG:-va-live-pg}"
port="${VIBEAUDIT_DEV_PG_PORT:-55433}"
# postgres:18.6, the digest the CI workflows pin.
image=public.ecr.aws/docker/library/postgres@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722
mkdir -p "$cache"
chmod 700 "$cache"

if [ ! -s "$cache/pgpass" ]; then
  (umask 077 && .venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(24), end="")' > "$cache/pgpass")
fi
if ! docker container inspect "$container" >/dev/null 2>&1; then
  # The password reaches docker through the environment, not the command line.
  POSTGRES_PASSWORD=$(cat "$cache/pgpass") docker run -d --name "$container" -e POSTGRES_PASSWORD -e POSTGRES_DB=vibeaudit \
    -p "127.0.0.1:$port:5432" "$image" >/dev/null
else
  docker start "$container" >/dev/null
fi
tries=0
until docker exec "$container" pg_isready -U postgres -q; do
  tries=$((tries + 1))
  [ "$tries" -lt 60 ] || { echo "PostgreSQL in $container did not become ready" >&2; exit 1; }
  sleep 1
done
# The container may have kept a password an earlier pgpass held; make it the current one. The password travels in the
# environment and is read inside psql, so no command line carries it.
PGPASS_NEW=$(cat "$cache/pgpass") docker exec -i -e PGPASS_NEW "$container" psql -U postgres -q -v ON_ERROR_STOP=1 <<'SQL'
\getenv pw PGPASS_NEW
ALTER USER postgres PASSWORD :'pw';
SELECT 'CREATE DATABASE vibeaudit_pipeline_test' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'vibeaudit_pipeline_test')\gexec
SQL

# The offline OSV database is a large download: fetched once, kept until removed.
if [ ! -s "$cache/osv/manifest.json" ]; then
  .venv/bin/python scripts/provision-offline-db.py "$cache/osv"
fi
.venv/bin/python scripts/provision-runtime.py --output "$cache/runtime-static.json" --offline-db "$cache/osv" \
  --work-root "$cache/workers" --static-only

printf '%s\n' "Ready. For tests/test_local_pipeline.py and the PostgreSQL tests:" \
  "  export VIBEAUDIT_DATABASE_URL=\"postgresql://postgres:\$(cat $cache/pgpass)@127.0.0.1:$port/vibeaudit_pipeline_test\"" \
  "  export VIBEAUDIT_TEST_RUNTIME_CONFIG=$cache/runtime-static.json"
