# Worker 執行環境

正式執行需要 Linux、本機 Docker daemon、PostgreSQL lease，以及寫在受信任 runtime profile 裡的映像 digest。HTTP API 只接受 profile 識別碼；agent 無法送出 Docker 選項或任意主機指令。

controller 會啟動一個獨立的 supervisor。supervisor 領取一次性的 capability，綁定 run、manifest、封存的案例、威脅模型、執行配方、到期時間與請求預算。每個對外請求在網路 I/O 之前，都需要 controller 新發的許可，以及已提交的 `sent` 紀錄。結果不明的請求維持終止狀態，必須在新的 run 中核對處理；恢復執行不會重播 worker 工作。

Worker 以 `--network none`、唯讀根檔案系統、不具任何 Linux capability、no-new-privileges，以及明確的 CPU、記憶體與 PID 上限執行。白箱 worker 使用 UID 65532，只拿到凍結的原始碼掛載。黑箱 worker 使用 UID 65533，沒有原始碼掛載。工具只能連到 loopback 上的 HTTP relay；relay 只能把封裝好的訊息送到 supervisor 掛載進來的 Unix socket。supervisor 強制檢查精確允許的 method／path、封存的案例與身分，解析並釘選目的地 IP，拒絕重新導向，並為每個請求預留 controller 共用的預算。憑證一直留在 supervisor。JSON 登入 token 可以存進案例專屬的 session 欄位；worker 看得到的本文與觀測紀錄，會遮蔽擷取到的與設定中的 token。

controller 管線關閉、取消、lease 到期或持久授權來源無法使用時，會先關閉 broker 與作用中的 socket，再終止容器。接著 supervisor 會 kill、等待並移除指定名稱的容器。無法確認清理完成時，結果是 `outcome_unknown`，絕不會當成成功。受信任的 supervisor 與本機 Docker daemon 屬於受信任運算基礎；主機遭入侵不在此邊界內。系統會檢查 Docker 是否可用，絕不會默默改在主機上直接執行。

`process_test` 是供監督測試使用的明確開發模式。它沒有網路或檔案系統隔離，拒絕執行掃描器指令，並回傳 `process_unisolated_test_only`。它不是正式環境的替代方案。

以驗證過的基礎映像 digest 建置最小 worker：

```sh
docker build --build-arg BASE_IMAGE=python@sha256:<verified-digest> -t vibeaudit-worker:test -f deploy/worker/Dockerfile deploy/worker
docker image inspect vibeaudit-worker:test --format '{{.Id}}'
```

`BASE_IMAGE` 必須是單行的 `<name>@sha256:<64 hex>`，否則建置失敗；`python:3.13-slim` 這類 tag 會被拒絕。這個參照會存在 OCI 標籤 `org.opencontainers.image.base.name`，而 `scripts/provision-runtime.py` 不會記錄沒有 digest 釘選標籤的 worker 映像。這些檢查能擋下誤用 tag 或過時、沒有標籤的映像，但不是來源證明。標籤是映像自己的宣告：任何能操作 Docker daemon 的帳號都能設定它；以有標籤的 worker 為 FROM 建出的映像會直接繼承標籤，不會經過這項檢查。因此 `.images.json` 附檔裡的 `base_image_label` 只記錄這項宣告，runtime 也不會再檢查。digest 本身仍須由操作者對照官方映像確認。

工具映像必須包含 `python3` 與固定版本的工具執行檔。靜態工具完全離線執行。OSV 需要另外佈建並驗證過的資料庫快照，目錄中要有 `osv-scanner/`；該目錄會以唯讀方式掛載到 `/opt/osv-db`。worker 不會下載任何資料庫。映像的安裝與拉取只在受信任的佈建階段進行。

`scripts/provision-runtime.py` 會查這個 tag 並記錄它的 image ID；它寫入的 lease TTL（10 秒）就是 Docker 整合測試使用的值。也可以把 `runtime.example.json` 複製到受保護的設定路徑，填入映像 digest 與選用的 `offline_db_dir`，再設定 `VIBEAUDIT_RUNTIME_CONFIG` 與其中引用的資料庫環境變數。work root 要放在原生 Linux 檔案系統上，且只限 controller／supervisor 帳號存取（Unix socket 路徑必須在作業系統長度上限內）。HTTP 目標的測試身分只能引用明確列入允許清單的 `VIBEAUDIT_` 環境變數。

設定 `VIBEAUDIT_TEST_DATABASE_URL` 與 `VIBEAUDIT_TEST_WORKER_IMAGE` 後，即可執行實際的本機整合測試。沒有這些變數時，真正的 Docker／PostgreSQL 檢查會明確 skip。不需要任何雲端模型帳號。

---
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
docker build --build-arg BASE_IMAGE=python@sha256:<verified-digest> -t vibeaudit-worker:test -f deploy/worker/Dockerfile deploy/worker
docker image inspect vibeaudit-worker:test --format '{{.Id}}'
```

The build fails unless `BASE_IMAGE` is a single line `<name>@sha256:<64 hex>`; a tag
such as `python:3.13-slim` is refused. The reference is kept in the OCI label
`org.opencontainers.image.base.name`, and `scripts/provision-runtime.py` refuses to
record a worker image without a digest-pinned label. These checks catch an accidental
tag or a stale unlabeled image; they are not provenance. The label is the image's own
claim: any account that can operate the Docker daemon can set it, and an image built
FROM a labeled worker inherits it without running this check, so `base_image_label` in the
`.images.json` side file records that claim only. The runtime does not re-check it. The
digest itself must still be checked against the official image by the operator.

Tool images must contain `python3` and the fixed tool executable. Static tools
are completely offline. OSV requires a separately provisioned and verified
database snapshot whose directory contains `osv-scanner/`; that directory is
mounted read-only at `/opt/osv-db`. No database download is performed by a
worker. Image installation/pulls occur only during trusted provisioning.

`scripts/provision-runtime.py` looks this tag up and records its image ID; the
lease TTL it writes (10 seconds) is the one the Docker integration runs used.
Or copy `runtime.example.json` to a protected configuration path, fill the image
digests and optional `offline_db_dir`, and set `VIBEAUDIT_RUNTIME_CONFIG` plus
the referenced database environment variable. Keep the work root private to
the controller/supervisor account on a native Linux filesystem (Unix socket
paths must fit the OS limit). HTTP target identities refer only to explicitly
allowlisted `VIBEAUDIT_` environment variables.

Run actual local integration tests with `VIBEAUDIT_TEST_DATABASE_URL` and
`VIBEAUDIT_TEST_WORKER_IMAGE` set. Tests without those variables explicitly
skip the real Docker/PostgreSQL checks. No live cloud-model account is needed.
