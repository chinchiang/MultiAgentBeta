# Linux 完整 Docker 整合測試

VALIDATION.md 的「重跑」只示範 tests/test_tool_runners.py。本文記錄以一般使用者帳號、Docker 與暫存 PostgreSQL 執行整個 tests/ 的步驟，以及 2026-10-03 實際遇到的設定問題。映像須先依 LINUX_SETUP.md 第 3 節 provision；能操作 Docker daemon 的帳號屬高權限信任邊界。

## 1. 暫存 PostgreSQL

沒有資料庫管理權限時，以一般使用者啟動只聽 unix socket 的實例。`--auth=trust` 只適用於這種僅供本機測試、用完即丟的實例。

```sh
/usr/lib/postgresql/18/bin/initdb -D /tmp/va-pg -U vibeaudit_test --auth=trust
mkdir -p /tmp/va-pgsock
/usr/lib/postgresql/18/bin/pg_ctl -D /tmp/va-pg -l /tmp/va-pg.log -o "-k /tmp/va-pgsock -p 55432 -c listen_addresses=''" start
# initdb 只建立角色，不會建立同名資料庫；測試 URL 指向的資料庫要自己建：
/usr/lib/postgresql/18/bin/psql -h /tmp/va-pgsock -p 55432 -U vibeaudit_test -d postgres -c "CREATE DATABASE vibeaudit_test OWNER vibeaudit_test"
```

## 2. 測試用 runtime profile

正式 profile 的 work_root（/var/lib/vibeaudit/workers）屬於專用控制帳號。以自己的帳號測試時另產生一份，讓 work_root 指向自己可寫的目錄；腳本會從本機 Docker 讀出 image ID，不必手抄。

```sh
.venv/bin/python scripts/provision-runtime.py --output /tmp/va-runtime.json --work-root /tmp/va-workers
mkdir -p /tmp/va-workers
```

## 3. 環境變數與執行

```sh
export PYTHONPATH=backend
export VIBEAUDIT_TEST_POSTGRES='postgresql:///vibeaudit_test?host=/tmp/va-pgsock&port=55432&user=vibeaudit_test'
export VIBEAUDIT_TEST_DATABASE_URL="$VIBEAUDIT_TEST_POSTGRES"
export VIBEAUDIT_DATABASE_URL="$VIBEAUDIT_TEST_POSTGRES"
export VIBEAUDIT_TEST_RUNTIME_CONFIG=/tmp/va-runtime.json
export VIBEAUDIT_TEST_WORKER_IMAGE="$(docker image inspect --format '{{.Id}}' vibeaudit-worker:test)"
export VIBEAUDIT_FIXTURE_IMAGE="$VIBEAUDIT_TEST_WORKER_IMAGE"
export VIBEAUDIT_INTEGRATION_IMAGE="$(docker image inspect --format '{{.Id}}' vibeaudit-tools:integration)"
export VIBEAUDIT_ZAP_IMAGE="$(docker image inspect --format '{{.Id}}' ghcr.io/zaproxy/zaproxy:2.17.0)"
export VIBEAUDIT_TEST_NODE="$(command -v node)"   # 必須是 Node 24
.venv/bin/python -m pytest tests -q -rs
```

本機整套約需 7 分鐘。需要收據時加上 `--junitxml=…`，放進 docs/ 前先執行 `python scripts/redact-receipts.py`。

## 2026-10-03 遇到的問題

| 現象 | 原因 | 處理 |
|---|---|---|
| 完整 pipeline 測試結束為 incomplete，gap 為 `[Errno 13] Permission denied: '/var/lib/vibeaudit/workers/…'` | 沿用正式 profile，work_root 不可寫 | 依第 2 節另產生 profile |
| ZAP 工具測試為 `outcome_unknown`，原因是 Worker exited without a valid result | 未設 VIBEAUDIT_ZAP_IMAGE，測試退回使用不含 ZAP 的工具映像 | 設定 VIBEAUDIT_ZAP_IMAGE |
| Web fixture 測試（含 login/logout）被跳過 | 找不到 Node 24：未設 VIBEAUDIT_TEST_NODE，PATH 也沒有 node | 設定 VIBEAUDIT_TEST_NODE |
| fixture protocol 測試通過，但沒有經過 Docker | 未設 VIBEAUDIT_FIXTURE_IMAGE 時，測試改用 process_test 後端，不會顯示為 skip | 設為 worker 映像 |
| 三個 API 測試讀到其他測試留下的 runs；另一個測試讀不到自己剛存的 run | create_app 會讀 VIBEAUDIT_DATABASE_URL，這些測試因此連到共用的 PostgreSQL，而不是自己 tmp_path 下的 SQLite | 已修正：tests/test_engine.py 與 tests/test_contracts_and_workspace.py 在每個測試前移除該變數 |

前四項是測試環境設定不完整；最後一項是測試本身依賴外部環境變數，已在程式碼中修正。結果與收據見 VALIDATION.md。

## 清理

```sh
/usr/lib/postgresql/18/bin/pg_ctl -D /tmp/va-pg stop
```

資料目錄 /tmp/va-pg 可保留，下次直接 `pg_ctl … start` 即可。

---
# Full Docker integration testing on Linux

The "re-run" in VALIDATION.md only demonstrates tests/test_tool_runners.py. This document records the steps for running the whole tests/ suite with a regular user account, Docker, and a throwaway PostgreSQL, as well as the configuration problems actually encountered on 2026-10-03. The images must first be provisioned as in section 3 of LINUX_SETUP.md; an account that can operate the Docker daemon is a high-privilege trust boundary.

## 1. Throwaway PostgreSQL

Without database administration rights, start, as a regular user, an instance that listens only on a unix socket. `--auth=trust` is suitable only for this kind of local-test-only, use-and-discard instance.

```sh
/usr/lib/postgresql/18/bin/initdb -D /tmp/va-pg -U vibeaudit_test --auth=trust
mkdir -p /tmp/va-pgsock
/usr/lib/postgresql/18/bin/pg_ctl -D /tmp/va-pg -l /tmp/va-pg.log -o "-k /tmp/va-pgsock -p 55432 -c listen_addresses=''" start
# initdb creates only the role, not a database with the same name; the database the test URL points to must be created yourself:
/usr/lib/postgresql/18/bin/psql -h /tmp/va-pgsock -p 55432 -U vibeaudit_test -d postgres -c "CREATE DATABASE vibeaudit_test OWNER vibeaudit_test"
```

## 2. Runtime profile for testing

The production profile's work_root (/var/lib/vibeaudit/workers) belongs to the dedicated control account. When testing under your own account, generate a separate profile whose work_root points to a directory you can write; the script reads the image IDs from the local Docker, so no manual copying is needed.

```sh
.venv/bin/python scripts/provision-runtime.py --output /tmp/va-runtime.json --work-root /tmp/va-workers
mkdir -p /tmp/va-workers
```

## 3. Environment variables and execution

```sh
export PYTHONPATH=backend
export VIBEAUDIT_TEST_POSTGRES='postgresql:///vibeaudit_test?host=/tmp/va-pgsock&port=55432&user=vibeaudit_test'
export VIBEAUDIT_TEST_DATABASE_URL="$VIBEAUDIT_TEST_POSTGRES"
export VIBEAUDIT_DATABASE_URL="$VIBEAUDIT_TEST_POSTGRES"
export VIBEAUDIT_TEST_RUNTIME_CONFIG=/tmp/va-runtime.json
export VIBEAUDIT_TEST_WORKER_IMAGE="$(docker image inspect --format '{{.Id}}' vibeaudit-worker:test)"
export VIBEAUDIT_FIXTURE_IMAGE="$VIBEAUDIT_TEST_WORKER_IMAGE"
export VIBEAUDIT_INTEGRATION_IMAGE="$(docker image inspect --format '{{.Id}}' vibeaudit-tools:integration)"
export VIBEAUDIT_ZAP_IMAGE="$(docker image inspect --format '{{.Id}}' ghcr.io/zaproxy/zaproxy:2.17.0)"
export VIBEAUDIT_TEST_NODE="$(command -v node)"   # must be Node 24
.venv/bin/python -m pytest tests -q -rs
```

The whole local run takes about 7 minutes. When receipts are needed, add `--junitxml=…`, and before putting them into docs/ first run `python scripts/redact-receipts.py`.

## Problems encountered on 2026-10-03

| Symptom | Cause | Fix |
|---|---|---|
| The full pipeline test ends incomplete with gap `[Errno 13] Permission denied: '/var/lib/vibeaudit/workers/…'` | The production profile was reused and its work_root is not writable | Generate a separate profile as in section 2 |
| The ZAP tool test is `outcome_unknown` because Worker exited without a valid result | VIBEAUDIT_ZAP_IMAGE was not set, so the test fell back to the tool image without ZAP | Set VIBEAUDIT_ZAP_IMAGE |
| The web fixture tests (including login/logout) are skipped | Node 24 not found: VIBEAUDIT_TEST_NODE is unset and there is no node in PATH | Set VIBEAUDIT_TEST_NODE |
| The fixture protocol tests pass but never go through Docker | When VIBEAUDIT_FIXTURE_IMAGE is not set, the tests switch to the process_test backend, which does not show up as a skip | Set it to the worker image |
| Three API tests read runs left behind by other tests; another test cannot read the run it just stored | create_app reads VIBEAUDIT_DATABASE_URL, so these tests connect to the shared PostgreSQL instead of the SQLite under their own tmp_path | Fixed: tests/test_engine.py and tests/test_contracts_and_workspace.py remove that variable before each test |

The first four items are incomplete test-environment configuration; the last item was the tests themselves depending on an external environment variable, which has already been fixed in the code. Results and receipts are in VALIDATION.md.

## Cleanup

```sh
/usr/lib/postgresql/18/bin/pg_ctl -D /tmp/va-pg stop
```

The data directory /tmp/va-pg can be kept; next time just run `pg_ctl … start`.
