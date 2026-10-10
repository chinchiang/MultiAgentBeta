# Linux / WSL2 操作指南

## 執行需求

Python 3.12+、Node 24（建置 UI／TS fixture）、PostgreSQL、支援 recursive read-only bind mount 的 Linux kernel/Docker（Docker 25 以上；supervisor 直接呼叫 Docker Engine API，與 daemon 協商版本，最高使用 1.52、最低需要 1.44），以及授權 staging。實際驗收版本見 VALIDATION.md。Windows 原生控制台可跑 demo；live 控制程序和 Docker workers 一起放在 Linux/WSL2。

模型、靶場與憑證不由安裝程序自動建立。以下下載與建置是管理者的明確 provisioning；評估期間不安裝套件、不拉取映像。

## 1. 安裝控制台

在專案根目錄執行：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock.txt
cd frontend
npm ci
npm run build
cd ..
```

已交付 frontend/dist 可直接提供本地 UI。Linux 啟動器也允許用 VIBEAUDIT_PYTHON 指定既有受測 venv。

requirements.lock.txt 為每個鎖定版本列出 PyPI 上所有發布檔的 sha256，pip 以 hash 檢查模式安裝：下載的檔案不符，或有依賴沒有鎖定，安裝都會中止，不會自動改抓其他版本。調整版本後執行 `python scripts/hash-lock.py --write` 重新產生 hash。

## 2. 資料庫與工作目錄

準備專用 PostgreSQL role/database，允許建立本工具的表與 LangGraph checkpoint。以 VIBEAUDIT_DATABASE_URL 保存連線資訊，勿把密碼寫進專案設定或 prompt。使用管理者預建的資料目錄，控制程序對其有權限；受測來源只放在明確准許的根目錄。

```sh
export VIBEAUDIT_DATABASE_URL='postgresql://USER:PASSWORD@127.0.0.1:5432/vibeaudit'
export VIBEAUDIT_DATA_DIR='/var/lib/vibeaudit/data'
export VIBEAUDIT_SOURCE_ROOTS='/srv/authorized-test-sources'
```

上列 USER/PASSWORD 是占位值。驗收使用 WSL 的本地 peer role，不代表產品要求以 root 執行；正式部署使用專用控制帳號。能操作 Docker daemon 的帳號屬高權限信任邊界。

## 3. 預建 worker 與工具

```sh
docker build --build-arg BASE_IMAGE=python@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 -t vibeaudit-worker:test deploy/worker
docker build -f deploy/scanners/Dockerfile.gitleaks -t vibeaudit-gitleaks:8.30.1 deploy/scanners
docker build -f deploy/scanners/Dockerfile.osv -t vibeaudit-osv:2.3.5 deploy/scanners
docker build -f deploy/worker/Dockerfile.tools.locked -t vibeaudit-tools:integration deploy/worker
docker pull semgrep/semgrep:1.153.0
docker pull ghcr.io/zaproxy/zaproxy:2.17.0
```

worker 的 `BASE_IMAGE` 必須是單行的 `<name>@sha256:<64 hex>`，否則建置失敗；provision-runtime.py 也不記錄沒有 digest 基礎映像標籤（`org.opencontainers.image.base.name`）的 worker。這個標籤是映像自己的宣告，只用來擋下誤用 tag，不是來源證明。映像標籤只用於 provisioning。下個步驟將本地實際 image ID 寫進設定；runner 只接受 immutable SHA256。工具映像的確切 Python/npm 鎖定檔在 deploy/worker/locks；Dockerfile.tools 保留原始 provisioning 配方，Dockerfile.tools.locked 使用捕獲的完整依賴鎖定檔。固定 image ID 與驗收版本另存於 docs/runtime-images.json。跨架構或重建後必須重新跑工具契約，不能假設 image ID 相同。

## 4. 離線漏洞資料與 runtime profile

```sh
.venv/bin/python scripts/provision-offline-db.py /opt/vibeaudit/osv
.venv/bin/python scripts/provision-runtime.py --output /etc/vibeaudit/runtime.json --offline-db /opt/vibeaudit/osv --work-root /var/lib/vibeaudit/workers
export VIBEAUDIT_RUNTIME_CONFIG='/etc/vibeaudit/runtime.json'
```

OSV provisioning 下載官方完整 PyPI/npm 生態系 archive，不外送本機依賴清單。資料日期、來源、雜湊與涵蓋範圍保存在 manifest.json；評估時再次固定該 manifest 和 archive hashes。離線模式不包含 commit-level matching，資料更新後為新的 resource version。

## 5. 啟動與配置

```sh
sh scripts/start-local.sh 8000
```

開啟終端機印出的 `http://127.0.0.1:8000/#token=…` 網址；沒有權杖無法建立 session。同一分頁重新整理不需權杖，新分頁需重新開啟該網址。需要固定權杖時先設定 `VIBEAUDIT_SESSION_TOKEN`（32–256 個 URL-safe 字元）。先確認工具清單，再配置 Commander 和三個 reviewer 的確切端點/model ID/family。金鑰填環境變數名稱，例如 VIBEAUDIT_ANTHROPIC_API_KEY（UI 選 Anthropic 時的預設名稱），不填值。VIBEAUDIT_DATABASE_URL、VIBEAUDIT_SESSION_TOKEN 等本工具設定，或值與其相同、值為 URL 的變數，都不能當作模型或目標憑證。部分推理模型（例如 gpt-5、o 系列）只接受預設 temperature，請將該欄留空；探測會在送出前回報 unsupported_parameter，不計費也不鎖住用量。cloud_allowed 仍需逐一列出 origin；local_only 只接受明確 loopback 模型端點。模型金鑰另須在啟動前以 VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS 綁定 origin，例如 `VIBEAUDIT_GATEWAY_KEY=https://llm.example.com,VIBEAUDIT_LOCAL_KEY=http://127.0.0.1:8001`；VIBEAUDIT_OPENAI_API_KEY 與 VIBEAUDIT_ANTHROPIC_API_KEY 預設綁定官方端點，可在此覆寫。沒有金鑰的本地端點不需綁定。

填入使用者提供的來源、staging、允許 IP、每個 METHOD/path、業務需求、帳號 reference、fixtures、部署識別/header，以及時間/請求/模型上限。允許 IP 不能是雲端 metadata、link-local、unspecified 或 multicast 位址，目標也不能是本控制台或其資料庫的 host:port。帳號 reference 指向的 VIBEAUDIT_* 憑證，須在啟動控制台的環境以 `VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS='VIBEAUDIT_ALICE_TOKEN=https://staging.example.test'` 綁定到目標 origin（多筆以逗號分隔），未綁定時預檢會拒絕。只有勾選「允許模型設計的案例使用此身分」的測試身分可被模型設計的案例使用；高權限帳號請勿勾選。來源目錄存的是通過 VIBEAUDIT_SOURCE_ROOTS 檢查、解析後的路徑；含 `..` 的路徑不會被讀取。正控制、reset、cleanup 也必須列在 scope 中；空 scope 禁止所有黑箱請求。預檢不進行漏洞探測。

## 6. 自有 Target Adapter

VIBEAUDIT_FIXTURE_CONFIG 可指向管理者編寫的 JSON registry。每個 profile 宣告 reset/session_reset/setup/cleanup、repetitions 及可選 collector_binding/collector_requests；case sealing 前會計算完整 lifecycle scope 與 profile hash。

普通 HTTP read 可用預先核定的 fixture marker；副作用案例必須有 reset/cleanup。no_unauthorized_commit 另需以可信 Python bootstrap 呼叫 register_effect_binding，供應 begin/collect_verified/close 的獨立 collector。不能從 LLM 或 target 載入任意程式。內建 synthetic-ai-v1/synthetic-web-v1 僅供隨附靶場，不能冒充一般產品的後端驗證。

promptfoo/PyRIT 等外部工具可在 setup、正控制、主測試、collector、cleanup 流程中執行，報告保留實際工具與 artifact hash。需要擷取及重用 session 的登入/登出案例目前使用原生 HTTP sequence；指定不支援該流程的外部工具時會 blocked，不會靜默改用另一個工具。

## 7. 驗收

先跑無模型憑證測試，再以實際三端點跑 probe 和完整流程。參照 VALIDATION.md 的環境變數啟用 PostgreSQL/Docker 整合測試。沒有端點時不要把合成 demo 改標為真實模型結果。

停止會先撤網再清理；outcome_unknown 不可直接恢復重播。確認靶場狀態並重置後，建立新 run 保留舊證據。

---
# Linux / WSL2 Operations Guide

## Prerequisites

Python 3.12+, Node 24 (to build the UI / TS fixtures), PostgreSQL, a Linux kernel/Docker that supports recursive read-only bind mounts (Docker 25 or newer; the supervisor calls the Docker Engine API directly and negotiates its version with the daemon, using at most 1.52 and needing at least 1.44), and an authorized staging area. See VALIDATION.md for the actual validated versions. The native Windows console can run the demo; the live control program and the Docker workers are placed together on Linux/WSL2.

Models, targets, and credentials are not created automatically by the installation procedure. The downloads and builds below are explicit provisioning by the administrator; no packages are installed and no images are pulled during an evaluation.

## 1. Install the console

Run from the project root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock.txt
cd frontend
npm ci
npm run build
cd ..
```

The shipped frontend/dist directly serves the local UI. The Linux launcher also allows VIBEAUDIT_PYTHON to point at an existing venv under test.

requirements.lock.txt lists, for each locked version, the sha256 of every release file on PyPI, and pip installs in hash-checking mode: if a downloaded file does not match, or any dependency is not locked, the install aborts — it never silently switches to another version. After adjusting versions, run `python scripts/hash-lock.py --write` to regenerate the hashes.

## 2. Database and working directories

Prepare a dedicated PostgreSQL role/database, allowed to create this tool's tables and LangGraph checkpoints. Keep the connection details in VIBEAUDIT_DATABASE_URL; never write the password into project settings or prompts. Use a data directory pre-created by the administrator, for which the control program has permissions; sources under test go only under explicitly approved root directories.

```sh
export VIBEAUDIT_DATABASE_URL='postgresql://USER:PASSWORD@127.0.0.1:5432/vibeaudit'
export VIBEAUDIT_DATA_DIR='/var/lib/vibeaudit/data'
export VIBEAUDIT_SOURCE_ROOTS='/srv/authorized-test-sources'
```

The USER/PASSWORD above are placeholders. Validation uses a local peer role in WSL, which does not mean the product requires running as root; production deployments use a dedicated control account. An account that can operate the Docker daemon is a high-privilege trust boundary.

## 3. Pre-build the worker and tools

```sh
docker build --build-arg BASE_IMAGE=python@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 -t vibeaudit-worker:test deploy/worker
docker build -f deploy/scanners/Dockerfile.gitleaks -t vibeaudit-gitleaks:8.30.1 deploy/scanners
docker build -f deploy/scanners/Dockerfile.osv -t vibeaudit-osv:2.3.5 deploy/scanners
docker build -f deploy/worker/Dockerfile.tools.locked -t vibeaudit-tools:integration deploy/worker
docker pull semgrep/semgrep:1.153.0
docker pull ghcr.io/zaproxy/zaproxy:2.17.0
```

The worker's `BASE_IMAGE` must be a single-line `<name>@sha256:<64 hex>` or the build fails; provision-runtime.py also refuses a worker without a digest base-image label (`org.opencontainers.image.base.name`). The label is the image's own claim; it catches an accidental tag and is not proof of provenance. Image tags are used for provisioning only. The next step writes the actual local image IDs into the configuration; the runner accepts only immutable SHA256 values. The exact Python/npm lockfiles for the tool images are in deploy/worker/locks; Dockerfile.tools keeps the original provisioning recipe, while Dockerfile.tools.locked uses the captured full dependency lockfiles. The pinned image IDs and validated versions are also stored in docs/runtime-images.json. After a cross-architecture build or any rebuild you must re-run the tool contracts; never assume the image IDs are unchanged.

## 4. Offline vulnerability data and the runtime profile

```sh
.venv/bin/python scripts/provision-offline-db.py /opt/vibeaudit/osv
.venv/bin/python scripts/provision-runtime.py --output /etc/vibeaudit/runtime.json --offline-db /opt/vibeaudit/osv --work-root /var/lib/vibeaudit/workers
export VIBEAUDIT_RUNTIME_CONFIG='/etc/vibeaudit/runtime.json'
```

OSV provisioning downloads the official, complete PyPI/npm ecosystem archives and never ships out local dependency lists. The data date, sources, hashes, and coverage are saved in manifest.json; pin that manifest and the archive hashes again at evaluation time. Offline mode does not include commit-level matching; after a data update this becomes a new resource version.

## 5. Start-up and configuration

```sh
sh scripts/start-local.sh 8000
```

Open the `http://127.0.0.1:8000/#token=…` URL printed by the terminal; without the token no session can be created. Refreshing the same tab needs no token; a new tab must reopen that URL. To pin a token, set `VIBEAUDIT_SESSION_TOKEN` first (32–256 URL-safe characters). Confirm the tool inventory first, then configure the exact endpoint/model ID/family for the Commander and the three reviewers. For keys, enter the environment variable name — for example VIBEAUDIT_ANTHROPIC_API_KEY (the default name when Anthropic is selected in the UI) — never a value. This tool's own settings such as VIBEAUDIT_DATABASE_URL and VIBEAUDIT_SESSION_TOKEN, variables whose values are identical to theirs, and variables whose values are URLs, must never be used as model or target credentials. Some reasoning models (e.g. gpt-5, the o-series) accept only the default temperature; leave that field empty. The probe reports unsupported_parameter before submission, with no billing and no usage lockout. cloud_allowed still requires each origin to be listed individually; local_only accepts only explicit loopback model endpoints. Before startup, also bind each model key to its origins in VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS, for example `VIBEAUDIT_GATEWAY_KEY=https://llm.example.com,VIBEAUDIT_LOCAL_KEY=http://127.0.0.1:8001`; VIBEAUDIT_OPENAI_API_KEY and VIBEAUDIT_ANTHROPIC_API_KEY are bound to their vendors' endpoints by default and can be rebound there. Local endpoints without a key need no binding.

Fill in the user-provided sources, staging, allowed IPs, every METHOD/path, business requirements, account references, fixtures, deployment identifiers/headers, and the time/request/model limits. Allowed IPs cannot be cloud metadata, link-local, unspecified or multicast addresses, and the target cannot be this console's or its database's host:port. The VIBEAUDIT_* credential an account reference names must be bound to the target origin in the console's environment, for example `VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS='VIBEAUDIT_ALICE_TOKEN=https://staging.example.test'` (comma-separate several entries); preflight refuses an unbound one. Only test identities marked to allow model-designed cases can be used by them; never mark a privileged account. A run keeps the resolved source path that passed the VIBEAUDIT_SOURCE_ROOTS check; a path containing `..` is never read. Positive controls, resets, and cleanups must also be listed in scope; an empty scope forbids all black-box requests. The pre-check performs no vulnerability probing.

## 6. Your own target adapter

VIBEAUDIT_FIXTURE_CONFIG can point to a JSON registry written by the administrator. Each profile declares reset/session_reset/setup/cleanup, repetitions, and the optional collector_binding/collector_requests; the full lifecycle scope and profile hash are computed before case sealing.

Ordinary HTTP reads can use pre-approved fixture markers; side-effect cases must have reset/cleanup. no_unauthorized_commit additionally requires calling register_effect_binding from a trusted Python bootstrap, supplying independent collectors for begin/collect_verified/close. Arbitrary code must never be loaded from an LLM or the target. The built-in synthetic-ai-v1/synthetic-web-v1 are for the bundled targets only and must not impersonate backend validation of a general product.

External tools such as promptfoo/PyRIT can be run within the setup, positive-control, main-test, collector, and cleanup phases; the report keeps the actual tool and artifact hashes. Login/logout cases that need to capture and reuse a session currently use the native HTTP sequence; when an external tool that does not support that flow is specified, the case is blocked — it never silently switches to another tool.

## 7. Acceptance

First run the tests without model credentials, then run the probe and the full flow against the actual three endpoints. See VALIDATION.md for the environment variables that enable the PostgreSQL/Docker integration tests. When there are no endpoints, never relabel the synthetic demo as real model results.

Stopping first withdraws the network and then cleans up; outcome_unknown must never be resumed and replayed directly. After confirming the target's state and resetting it, create a new run and keep the old evidence.
