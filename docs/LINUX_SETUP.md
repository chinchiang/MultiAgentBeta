# Linux / WSL2 操作指南

## 執行需求

Python 3.12+、Node 24（建置 UI／TS fixture）、PostgreSQL、支援 recursive read-only bind mount 的 Linux kernel/Docker，以及授權 staging。實際驗收版本見 VALIDATION.md。Windows 原生控制台可跑 demo；live 控制程序和 Docker workers 一起放在 Linux/WSL2。

模型、靶場與憑證不由安裝程序自動建立。以下下載與建置是管理者的明確 provisioning；評估期間不安裝套件、不拉取映像。

## 1. 安裝控制台

在專案根目錄執行：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock.txt
cd frontend
npm ci
npm run build
cd ..
```

已交付 frontend/dist 可直接提供本地 UI。Linux 啟動器也允許用 VIBEAUDIT_PYTHON 指定既有受測 venv。

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

映像標籤只用於 provisioning。下個步驟將本地實際 image ID 寫進設定；runner 只接受 immutable SHA256。工具映像的確切 Python/npm 鎖定檔在 deploy/worker/locks；Dockerfile.tools 保留原始 provisioning 配方，Dockerfile.tools.locked 使用捕獲的完整依賴鎖定檔。固定 image ID 與驗收版本另存於 docs/runtime-images.json。跨架構或重建後必須重新跑工具契約，不能假設 image ID 相同。

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

開啟終端機印出的 `http://127.0.0.1:8000/#token=…` 網址；沒有權杖無法建立 session。需要固定權杖時先設定 `VIBEAUDIT_SESSION_TOKEN`（32–256 個 URL-safe 字元）。先確認工具清單，再配置 Commander 和三個 reviewer 的確切端點/model ID/family。金鑰填環境變數名稱，例如 VIBEAUDIT_CLAUDE_KEY，不填值。cloud_allowed 仍需逐一列出 origin；local_only 只接受明確 loopback 模型端點。

填入使用者提供的來源、staging、允許 IP、每個 METHOD/path、業務需求、帳號 reference、fixtures、部署識別/header，以及時間/請求/模型上限。正控制、reset、cleanup 也必須列在 scope 中；空 scope 禁止所有黑箱請求。預檢不進行漏洞探測。

## 6. 自有 Target Adapter

VIBEAUDIT_FIXTURE_CONFIG 可指向管理者編寫的 JSON registry。每個 profile 宣告 reset/session_reset/setup/cleanup、repetitions 及可選 collector_binding/collector_requests；case sealing 前會計算完整 lifecycle scope 與 profile hash。

普通 HTTP read 可用預先核定的 fixture marker；副作用案例必須有 reset/cleanup。no_unauthorized_commit 另需以可信 Python bootstrap 呼叫 register_effect_binding，供應 begin/collect_verified/close 的獨立 collector。不能從 LLM 或 target 載入任意程式。內建 synthetic-ai-v1/synthetic-web-v1 僅供隨附靶場，不能冒充一般產品的後端驗證。

promptfoo/PyRIT 等外部工具可在 setup、正控制、主測試、collector、cleanup 流程中執行，報告保留實際工具與 artifact hash。需要擷取及重用 session 的登入/登出案例目前使用原生 HTTP sequence；指定不支援該流程的外部工具時會 blocked，不會靜默改用另一個工具。

## 7. 驗收

先跑無模型憑證測試，再以實際三端點跑 probe 和完整流程。參照 VALIDATION.md 的環境變數啟用 PostgreSQL/Docker 整合測試。沒有端點時不要把合成 demo 改標為真實模型結果。

停止會先撤網再清理；outcome_unknown 不可直接恢復重播。確認靶場狀態並重置後，建立新 run 保留舊證據。
