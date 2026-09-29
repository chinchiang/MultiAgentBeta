# Worker runtime

Production execution requires Linux, a local Docker daemon, PostgreSQL leases,
and image digests in a trusted runtime profile. The HTTP API accepts a profile
identifier; agents cannot submit Docker options or arbitrary host commands.

The controller starts an independent supervisor. The supervisor claims a
single-use capability binding the run, manifest, sealed case, threat model,
recipe, expiration and request budget. Every outbound request requires a fresh
controller grant and a committed `sent` journal before network I/O. Unknown
outcomes remain terminal and must be reconciled in a new run; resume does not
replay the worker task.

Workers run with `--network none`, a read-only root filesystem, no Linux
capabilities, no-new-privileges, and explicit CPU, memory and PID limits. White
workers use UID 65532 and receive only the frozen source mount. Black workers
use UID 65533 and receive no source mount. Tools reach a loopback HTTP relay;
the relay can only send framed messages to the supervisor's mounted Unix
socket. The supervisor enforces the exact allowed method/path, sealed case and
identity, resolves and pins the destination IP, denies redirects and reserves
the shared controller budget for every request. Credentials remain in the
supervisor. JSON login tokens may be captured into a case-local session slot;
worker-visible bodies and observations redact captured and configured tokens.

Controller pipe closure, cancellation, expired leases or unavailable durable
authority close the broker and active sockets before container termination.
The supervisor then kills/waits/removes the named container. Failure to verify
cleanup yields `outcome_unknown`, never success. The trusted supervisor and
local Docker daemon remain part of the trusted computing base; host compromise
is outside this boundary. Docker availability is checked and never silently
falls back to host execution.

`process_test` is an explicit development mode for supervision tests. It has
no network or filesystem isolation, refuses scanner commands, and returns
`process_unisolated_test_only`. It is not a production alternative.

Build the minimal worker using a verified base digest:

```sh
docker build --build-arg BASE_IMAGE=python@sha256:<verified-digest> -t vibeaudit-worker:local -f deploy/worker/Dockerfile deploy/worker
docker image inspect vibeaudit-worker:local --format '{{.Id}}'
```

Tool images must contain `python3` and the fixed tool executable. Static tools
are completely offline. OSV requires a separately provisioned and verified
database snapshot whose directory contains `osv-scanner/`; that directory is
mounted read-only at `/opt/osv-db`. No database download is performed by a
worker. Image installation/pulls occur only during trusted provisioning.

Copy `runtime.example.json` to a protected configuration path, fill the image
digests and optional `offline_db_dir`, and set `VIBEAUDIT_RUNTIME_CONFIG` plus
the referenced database environment variable. Keep the work root private to
the controller/supervisor account on a native Linux filesystem (Unix socket
paths must fit the OS limit). HTTP target identities refer only to explicitly
allowlisted `VIBEAUDIT_` environment variables.

Run actual local integration tests with `VIBEAUDIT_TEST_DATABASE_URL` and
`VIBEAUDIT_TEST_WORKER_IMAGE` set. Tests without those variables explicitly
skip the real Docker/PostgreSQL checks. No live cloud-model account is needed.
