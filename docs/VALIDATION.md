# 0.2.0 本地驗證紀錄

驗證日期：2026-09-24；審查後續修正後於 2026-10-02 重跑 Windows 全套回歸與前端建置；2026-10-03 深入審查的修正完成後，在 WSL2/Linux 重跑全套回歸（含 PostgreSQL 整合與 Node 24 fixture）、前端型別檢查與 production build、真 API + React SSR 契約檢查，並以 Docker 29.1.3 執行含全部 Docker 整合的 Linux 全套回歸。依使用者指定，本次完成工程及不需要模型憑證的本地整合。**未呼叫真實 Claude、OpenAI 或 Nemotron；未證明多模型減偏、漏洞檢出率或成本改善。**

本次已實際使用 Windows 控制台、WSL2/Linux、Docker 29.1.3、PostgreSQL 18.6 及固定版本的八種安全工具。Windows 為 Python 3.12.14，Linux 測試 venv 為 Python 3.14.4，Node 為 24.19.0。完整 Python/npm 依賴與工具映像鎖定檔隨原始碼交付。映像與離線 OSV 資料本身不放進 ZIP。

## 驗收結果

測試組互有重疊，**不可將各列相加當作不重複測試數**。JUnit 的 successful records 包含另外輸出的 subtests；下表使用 pytest 顯示的測試數。

| 驗收 | 實際結果 | 證據 |
|---|---|---|
| Linux 全套回歸（2026-10-03，現行程式碼） | 344 passed、21 skipped、4 subtests passed；PostgreSQL 18.6 整合（原子回滾、checkpoint 與 resume、lease 並行 claim）與 Node 24 Web fixture 皆實際執行；skips 為 20 項需要 Docker 映像的整合及 1 項 Windows 專屬 | linux-regression.xml |
| Linux 全套回歸含 Docker 整合（2026-10-03，現行程式碼） | 364 passed、1 skipped、4 subtests passed；隔離 worker、三種離線掃描器、五種動態工具、以 Docker 後端執行的 fixture protocol 與完整 pipeline 皆實際執行，另含 PostgreSQL 18.6 整合與 Node 24 Web fixture；唯一的 skip 為 Windows 專屬 | linux-docker-integration.xml |
| Windows 全套回歸（2026-10-02） | 279 passed、25 skipped、4 subtests passed | windows-regression.xml |
| PostgreSQL、隔離 worker、完整工作流 | 27 passed、4 deselected | postgres-pipeline-integration.xml |
| Fixture、重置、停止與故障路徑 | 24 passed、3 skipped、4 subtests passed | runtime-fixture-integration.xml |
| 最終流程與政策檢查 | 45 passed、14 skipped | final-guards.xml |
| 動態工具及 AI lifecycle、完整依賴鎖定映像 | 27 passed；零失敗、零跳過 | tool-integration-release.xml |
| Schemathesis header 修正 | 2 passed、25 deselected | schemathesis-header-regression.xml |
| 三種離線掃描器的已知問題偵測 | 3 passed | scanner-integration-release.xml |
| 前端型別檢查及 production build（2026-10-03） | 通過，32 modules；以鎖定依賴重建兩次，產物與 frontend/dist 逐位元組相同 | frontend/dist |
| Edge 真實瀏覽器 | 三種匯出、保存專案、追溯、建立複測；0 page errors | browser-validation.json |
| 真 FastAPI + React SSR/API | 三份合成審查、fail/pass/inconclusive、七份證據、五分頁、三種匯出及 HTML 跳脫；2026-10-03 以現行程式碼重跑通過，另確認只帶 session cookie 時 /api/session 與 /api/runs 拒絕且不洩漏 CSRF token，並以 Node 驗證 fetch 版 SSE 與下載 | api-ssr-validation.json |
| Python 相依一致性 | pip check 通過 | requirements.lock.txt |

兩份 Linux 全套回歸（含與不含 Docker 整合）、前端建置與 SSR/API 契約代表 2026-10-03 的現行程式碼；Windows 全套回歸是 2026-10-02 的結果。其餘各列是 2026-09-24 的結果。隔離 worker、掃描器與動態工具整合在 10-03 的修正（session 協定、supervisor 失敗分類、staging 生命週期等）之後，已由 linux-docker-integration.xml 重新驗證，表中 09-24 的分項收據保留作為當時的紀錄。取得這份收據前的幾次執行有失敗：四項是測試本身依賴外部環境變數（已修正，見下方第 11 項），其餘來自測試主機的環境變數與 runtime profile 設定不完整，詳見 DOCKER_INTEGRATION_TESTING.md。Edge 真實瀏覽器檢查在 10-03 的修正之後尚未重跑，不代表目前的程式碼。Windows 的 skips 包含需要 Linux/Docker/PostgreSQL、POSIX 程序或平台 symlink 能力的案例；已另在 Linux 執行的部分以上述 Linux 報告為準。Fixture 那組的三個 skips 包含未設定的 PostgreSQL 測試條件及 Windows 專屬路徑；PostgreSQL 情境由另一組補驗。最終政策檢查中的十四項 Docker 整合另行執行，沒有把 skip 當成 pass。

原始逐項名稱、耗時與 skip 原因見 XML；validation-summary.json 由 scripts/summarize-validation.py 自動讀取，沒有用 LLM 補造結果。收據中的主機名與使用者帳號已由 scripts/redact-receipts.py 遮罩（只改 hostname 屬性與家目錄的帳號段，測試、計數、耗時與原因不變）；先前 commit 的版本仍留在 git 歷史中。release-guards.xml、local-pipeline.xml、tool-integration.xml 為較早通過的重疊檢查，不另加計。

docs/history 保留 Schemathesis header 修正前的兩份失敗收據，分別為 25 passed/2 failed 與 4 passed/1 failed；共同原因是範例加入未封存的 header，政策層拒絕後正確保留 inconclusive。修正後結果見上表；不把歷史失敗隱藏成成功。

## 實際驗證的路徑

- 以合成模型契約驅動完整白箱、威脅、需求、案例、真 Docker HTTP 與 PostgreSQL checkpoint/job ledger 流程；另一變體同時執行真 Semgrep、Gitleaks、OSV。合成模型輸出不冒充供應商推理結果。
- PostgreSQL 原子提交回滾、並行 lease claim、journal 恢復與不重複執行。控制程序 hard-crash／衍生子程序的故障注入使用真 POSIX 程序及 process_test 後端；Docker 的實際身分、網路、掛載及正常清理另有整合測試。沒有把程序後端故障測試冒充所有 Docker daemon 故障情境；SQLite demo 測試也不代替 PostgreSQL。
- 真容器以非 root 身分及 network=none 執行，黑箱沒有原始碼或 Docker socket；獨立 supervisor 中介目標連線。停止先撤銷通訊，再終止 worker。
- ZAP 2.17.0、Schemathesis 4.28.0、Playwright 1.63.0、promptfoo 0.123.1、PyRIT 1.1.0 使用固定案例與正反例。工具檢查結果不能取代副作用 oracle。
- Semgrep 1.153.0、Gitleaks 8.30.1、OSV-Scanner 2.3.5 使用隨附規則、合成 repository 與完整 PyPI/npm 官方離線資料。資料來源及內容 hash 在 osv-database-manifest.json。
- TypeScript Web fixture 的 BOLA/登出、Python AI fixture 的合成 RAG、工具事件、sink、reset/cleanup。原生 AI fixture 每次五個獨立試驗；外部 AI 工具組合驗收每個正反例各兩次。
- 真 LiteLLM 1.102.1 SDK 配合合成 HTTP transport，涵蓋 OpenAI、OpenAI-compatible、NIM、Anthropic 的成功、redirect、限流及服務錯誤。每次授權限制一次 dispatch，沒有雲端模型流量或費用。
- Desktop 1440px 與 mobile 390px 沒有整頁水平溢出。不可信報告文字沒有被當作 HTML 執行。這不是完整無障礙或跨瀏覽器認證。

## 測試中修正的問題

1. 模型 SDK 的隱性 tokenizer 下載、NIM retry/fallback 行為：改用核對 hash 的隨附資產與單次 dispatch transport。
2. 結果及 journal 分開保存的重播窗口：改成共同交易提交；送出後未知結果阻擋自動重播。
3. 用量未知仍可恢復呼叫：持久化 unknown usage 並禁止繼續付費模型工作。
4. 白箱路徑競態、symlink/hardlink 及掛載限制：拒絕不安全來源；Linux 使用 descriptor 路徑檢查與 recursive read-only mount。
5. Fixture cleanup 使用與主操作相同的冪等鍵：將 setup、execution、cleanup 分開，確保實際重置與清理各自執行。
6. Windows fixture launcher 退出後仍可能留子程序：使用 Job Object 管理程序樹，並等待實際監聽埠關閉。
7. 動態工具省略空身分 header；ZAP 使用固定絕對啟動路徑。Schemathesis 範例改用既有案例 header，不放寬未授權 headers。
8. 複測視窗在 findings 載入前初始化：開啟時更新可選項；真瀏覽器驗證成功建立關聯複測。
9. 外部 AI 工具與 fixture lifecycle 組合：執行所選工具並保留 tool receipt，沒有偷偷替換成原生 HTTP。
10. Commander 的派工計畫實際套用（reviewers 並行執行，順序只決定紀錄排列，不影響各自的輸入）；Reporter 只能重排既有 finding IDs，不能補造或升級證據。
11. API 與工作區測試在設定 VIBEAUDIT_DATABASE_URL 時會連到共用的 PostgreSQL，讀到其他測試留下的 runs：這兩個測試模組在每個測試前移除該變數，改用各自 tmp_path 下的 SQLite。

## 映像與可重現性

runtime-images.json 保存 provision 時讀出的 image IDs。工具依賴先以實際工作映像驗證，再以 deploy/worker/locks 的完整 Python/npm 鎖定檔重建。測試使用的 image ID 及對應報告另見 image-validation.json。

固定版本與 hash 提供可追溯輸入，不保證所有 CPU 架構產出完全相同的 image ID。Dockerfile 仍包含作業系統套件安裝，系統套件來源未作完整時間快照；換環境重建必須重新驗收。所有來源、工具、規則、標準和模型分別保留授權。

## 示範與效果比較的界線

sample-report.json / .md 是實際本地合成 demo 的匯出。它刻意包含缺少副作用觀測的 inconclusive，整體標為 incomplete；這是驗證「不能假通過」的示例，不表示工程流程沒有執行完。

benchmarks/results-synthetic 有七組、每組六件的 42 次合成比較，用於驗證預算、分組、記錄與指標管線。results-local 的本地 AST 基線實際讀取樣本；沒有模型端點的組別明列 blocked。沒有人工核定的完整 ground truth 與真模型輸出時，正式 efficacy metrics 保持 null，不發布減偏或 recall 改善結論。

已知限制：runner 不提供人工裁定流程。gold 的 human_reviewed、reviewers 與 oracle_evidence 是宣告欄位，只檢查格式（至少兩個不同姓名、證據清單非空），不能證明審核確實發生。模型的未知 finding 列於 unadjudicated_ids，沒有盲審 matching 介面可回填為 TP／FP，因此 precision 維持 null。正式研究須在工具外完成兩人審核、分歧仲裁與盲審 matching，再產生新的 gold。

## 尚未驗證或不包含的能力

- 真實三個模型的確切型號、端點、額度、用量與模型品質；使用者自己的 staging 和後端觀測。這些依使用者決定留待配置完成後驗收。
- 任意 repository/framework 的完整語意分析、無限長程式碼、全站探索與主動 fuzz、任意瀏覽器腳本。此版動態工具只執行核准的有限案例。
- promptfoo/PyRIT 的全部上游插件或任意多步驟紅隊工作流；本版驗證固定受控 target + fixture/effect protocol。
- 跨主機高可用部署、macOS live worker、多人 SaaS、獨立第三方滲透審查或法證級不可竄改儲存。
- 五次未觀測到違規不代表安全；mock 工具與 sink 不證明真實後端授權正確。標準目錄有 462 個 canonical IDs，不等於已測完所有標準。

## 重跑

Windows：安裝後執行 scripts/verify.ps1；Linux 使用 scripts/verify-linux.sh。啟用真整合前設定下列環境變數，值必須來自自己的本地 provisioning：

```sh
export PYTHONPATH=backend
export VIBEAUDIT_TEST_POSTGRES='postgresql:///vibeaudit_test?host=/var/run/postgresql&user=YOUR_TEST_ROLE'
export VIBEAUDIT_TEST_DATABASE_URL="$VIBEAUDIT_TEST_POSTGRES"
export VIBEAUDIT_DATABASE_URL="$VIBEAUDIT_TEST_POSTGRES"
export VIBEAUDIT_TEST_RUNTIME_CONFIG='/etc/vibeaudit/runtime.json'
export VIBEAUDIT_INTEGRATION_IMAGE='sha256:YOUR_VERIFIED_TOOL_IMAGE'
export VIBEAUDIT_ZAP_IMAGE='sha256:YOUR_VERIFIED_ZAP_IMAGE'
export VIBEAUDIT_FIXTURE_IMAGE='sha256:YOUR_VERIFIED_WORKER_IMAGE'
export VIBEAUDIT_TEST_WORKER_IMAGE="$VIBEAUDIT_FIXTURE_IMAGE"
python -m pytest tests/test_tool_runners.py -q
```

verify-linux.sh 只在設定 `VIBEAUDIT_JUNIT_XML` 時寫出 JUnit 收據；放進 docs/ 前先執行 `python scripts/redact-receipts.py`。沒有 PostgreSQL 管理權限時，可用已安裝的 `initdb` 與 `pg_ctl` 在暫存目錄以一般使用者啟動只聽 unix socket 的測試實例（例如 `-o "-k /tmp/pgsock -p 55432 -c listen_addresses=''"`），再把上面的 URL 指向它；2026-10-03 的 Linux 收據即以此方式取得。Web fixture 測試以 `VIBEAUDIT_TEST_NODE` 指定 Node 24。其他整合測試所需旗標以各 tests/test_*.py 的明確 skip 條件為準；例外是未設 VIBEAUDIT_FIXTURE_IMAGE 時，fixture protocol 測試會改用 process_test 後端，不會顯示為 skip。以一般使用者帳號跑整個 tests/（含 Docker 整合）的步驟，以及 runtime profile 的 work_root 須可寫等常見設定錯誤，見 DOCKER_INTEGRATION_TESTING.md。完整 Linux provisioning、憑證 reference、fixtures、scope 與資料庫設定見 LINUX_SETUP.md。Browser smoke 的環境變數見 frontend/scripts/browser-smoke.cjs；SSR 指定 `node frontend/scripts/contract-smoke.mjs --base-url http://127.0.0.1:8002`。不同埠請替換為自己的 loopback 控制台。
