# 0.2.1 本地驗證紀錄

驗證日期：2026-09-24；審查後續修正後於 2026-10-02 重跑 Windows 全套回歸與前端建置；2026-10-03 深入審查的修正完成後，在 WSL2/Linux 重跑全套回歸（含 PostgreSQL 整合與 Node 24 fixture）、前端型別檢查與 production build、真 API + React SSR 契約檢查，並以 Docker 29.1.3 執行含全部 Docker 整合的 Linux 全套回歸；2026-10-04 第三輪審查修正（controller 狀態回收、worker 生命週期 teardown 與期限對齊、lease 日誌 result/request 綁定與已完成任務重用、死碼清理等，PR #6）合併後，在 Linux 重跑兩份全套回歸、前端型別檢查與 production build，Docker 整合包含隔離 worker、三種離線掃描器、五種動態工具與完整 pipeline，並以現行程式碼重跑 SSR/API 契約檢查（含 fetch 版 SSE 與下載）；2026-10-05 加入盲審 matching 工具與裁定檔範例後，重跑兩份 Linux 全套回歸、Windows 全套回歸、前端型別檢查與 production build、SSR/API 契約與 Edge 真實瀏覽器檢查，並在 Windows Python 3.12.10 以 `--require-hashes` 驗證全新 venv 安裝；同日完成 reviewer 名稱正規化與 worksheet 理由只取獨立階段的安全強化後，上述全部收據再次更新。依使用者指定，本次完成工程及不需要模型憑證的本地整合。**未呼叫真實 Claude、OpenAI 或 Nemotron；未證明多模型減偏、漏洞檢出率或成本改善。**

本次已實際使用 Windows 控制台、WSL2/Linux、Docker 29.1.3、PostgreSQL 18.6 及固定版本的八種安全工具。09-24 原始驗證主機的 Windows 收據為 Python 3.12.14；10-05 的 Windows 收據為 Python 3.13.15（另以 Windows Python 3.12.10 驗證雜湊鎖定安裝），Linux 測試 venv 為 Python 3.14.4，Node 為 24.19.0。完整 Python/npm 相依套件與工具映像鎖定檔隨原始碼交付。映像與離線 OSV 資料本身不放進 ZIP。

## 驗收結果

測試組互有重疊，**不可將各列相加當作不重複測試數**。JUnit 的 successful records 包含另外輸出的 subtests；下表使用 pytest 顯示的測試數。

| 驗收 | 實際結果 | 證據 |
|---|---|---|
| Linux 全套回歸（2026-10-05，現行程式碼） | 363 passed、21 skipped、4 subtests passed；PostgreSQL 18.6 整合（原子回復、checkpoint 與 resume、lease 並行 claim）與 Node 24 Web fixture 皆實際執行；skips 為 20 項需要 Docker 映像的整合及 1 項 Windows 專屬 | linux-regression.xml |
| Linux 全套回歸含 Docker 整合（2026-10-05，現行程式碼） | 383 passed、1 skipped、4 subtests passed；隔離 worker、三種離線掃描器、五種動態工具、以 Docker 後端執行的 fixture protocol 與完整 pipeline 皆實際執行，另含 PostgreSQL 18.6 整合與 Node 24 Web fixture；唯一的 skip 為 Windows 專屬。盲審 matching 工具的 10 項測試也在此收據範圍內 | linux-docker-integration.xml |
| Linux 全套回歸含 Docker 整合（2026-10-06，現行程式碼） | 508 passed、15 skipped、4 subtests passed；Python 3.12.3、Docker 29.6.2、PostgreSQL 16.14、Node 24.21.0。隔離 worker、白箱容器不掛 broker、黑箱 http_case 固定序列、三種離線掃描器、以 Docker 後端執行的 fixture protocol（含 supervisor 紀錄判定）與完整 pipeline 皆實際執行。14 項 skip 是這台主機沒有建置 tools 與 ZAP 映像，所以五種動態工具這次沒有重驗，以 10-05 收據為準；另 1 項為 Windows 專屬 | linux-docker-integration-2026-10-06.xml |
| Linux 全套回歸含 Docker 整合（2026-10-09，現行程式碼） | 559 passed、1 skipped、4 subtests passed；Python 3.13.16、Docker 29.8.2、PostgreSQL 16.15、Node 24.21.0。G4 第 12–24 輪合併後重驗：隔離 worker、三種離線掃描器（含離線 OSV 資料）、五種動態工具、以 Docker 後端執行的 fixture protocol 與完整 pipeline 皆實際執行，另含 PostgreSQL 整合與 Node 24 Web fixture；唯一的 skip 為 Windows 專屬。工具映像因建置環境的 HTTPS 代理，以 BuildKit secret 掛載代理 CA 只供安裝步驟使用後由 Dockerfile.tools.locked 的鎖定檔重建，image ID 與 runtime-images.json 不同 | linux-docker-integration-2026-10-09.xml |
| Windows 全套回歸（2026-10-05，現行程式碼） | 359 passed、25 skipped、4 subtests passed | windows-regression.xml |
| PostgreSQL、隔離 worker、完整工作流 | 27 passed、4 deselected | postgres-pipeline-integration.xml |
| Fixture、重置、停止與故障路徑 | 24 passed、3 skipped、4 subtests passed | runtime-fixture-integration.xml |
| 最終流程與政策檢查 | 45 passed、14 skipped | final-guards.xml |
| 動態工具及 AI lifecycle、完整相依套件鎖定映像 | 27 passed；零失敗、零跳過 | tool-integration-release.xml |
| Schemathesis header 修正 | 2 passed、25 deselected | schemathesis-header-regression.xml |
| 三種離線掃描器的已知問題偵測 | 3 passed | scanner-integration-release.xml |
| 前端型別檢查及 production build（2026-10-05） | 通過，32 modules；以鎖定的相依套件重建，產物與 frontend/dist 逐位元組相同 | frontend/dist |
| Chromium 真實瀏覽器（2026-10-09，現行程式碼） | Playwright 1.49.1 驅動 Chromium 141 headless：三種匯出、保存專案、追溯、建立複測、中英介面切換；0 page errors、無水平溢位。取代 2026-10-05 的 Edge 154 收據（保留在 git 歷史） | browser-validation.json |
| 真 FastAPI + React SSR/API | 三份合成審查、fail/pass/inconclusive、七份證據、五分頁、三種匯出及 HTML 跳脫；2026-10-05 以現行程式碼重跑通過（含證據裁決控制台），另確認只帶 session cookie 時 /api/session 與 /api/runs 拒絕且不洩漏 CSRF token，並以 Node 驗證 fetch 版 SSE 與下載 | api-ssr-validation.json |
| 突變測試（2026-10-10，現行程式碼） | mutmut 3.8.0 對 `policy.py`、`adapters.py`、`catalog.py`、`lease.py`、`snapshot.py`、`messages.py` 產生 4,620 個突變，以單元測試套件逐一測試（lease 測試含 PostgreSQL）。第三輪逐一讀過每個存活突變的 diff：可觀測的差異補精確斷言（整句訊息、每個邊界值、以欄位確切名稱讀取的選用欄位、PostgreSQL 列鎖下的讀取、觀測與證據的完整內容），等價的標 `# pragma: no mutate` 並附一句理由。結果：抓到 4,546、逃過 73（1 個逾時不計）。剩下的在 `adapters.py` 36、`policy.py` 14、`snapshot.py` 12、`lease.py` 8、`catalog.py` 3；`messages.py` 0，幾乎都是等價突變（`.upper()` 之前的小寫預設、別處已擋下的缺鍵預設、Linux 上為 0 的平台常數、`None` 讀作 False 的 json 參數）。這些數字是 `tests/mutation-baseline.json` 的各模組上限（另記每個函式的數字供 pull request 的 `--changed` 使用），由第一輪的 1,301、第二輪的 623 降下來；只有補測試才能再降。完整跑一律從空的 `mutants/` 開始（腳本自行清除）：mutmut 會沿用文字未變的突變的舊結果，不讓新測試碰到它們。 | 本機 `scripts/mutation-test.py` 執行紀錄；`.github/workflows/mutation.yml` 預設關閉（repository variable `VIBEAUDIT_MUTATION=true` 才每週重跑，手動 dispatch 一律跑） |
| Python 相依一致性 | pip check 通過；鎖定檔附 hash 後（2026-10-03；2026-10-04 重跑），以 `--require-hashes` 在全新 venv 安裝通過：Linux Python 3.14.4、Windows Python 3.13.15 與 Windows Python 3.12.10（2026-10-05）實際裝上的套件與鎖定檔逐項相同，Linux 那個 venv 不含 Docker 的測試為 350 passed、21 skipped | requirements.lock.txt |

兩份 Linux 全套回歸（含與不含 Docker 整合）、前端建置、SSR/API 契約與 Windows 全套回歸都代表 2026-10-05 的現行程式碼。2026-10-06 在 G4 第 5–11 輪審查修正合併後，另以含 Docker 整合的 Linux 全套回歸重驗；取得收據前的失敗與原因見 DOCKER_INTEGRATION_TESTING.md 的「2026-10-06 遇到的問題」。其餘各列是 2026-09-24 的結果。隔離 worker、掃描器與動態工具整合在 10-03 的修正（session 協定、supervisor 失敗分類、staging 生命週期等）與 10-04 的修正（supervisor teardown 統一、控制器期限對齊、日誌重用、guardian 暫時性錯誤容忍等）之後，已由 linux-docker-integration.xml 重新驗證，表中 09-24 的分項收據保留作為當時的紀錄。取得 10-03 收據前的幾次執行有失敗：四項是測試本身依賴外部環境變數（已修正，見下方第 11 項），其餘來自測試主機的環境變數與 runtime profile 設定不完整，詳見 DOCKER_INTEGRATION_TESTING.md。Edge 真實瀏覽器檢查已於 10-05 以現行程式碼重跑通過（frontend/scripts/browser-smoke.cjs，系統 Edge 154 headless）；SSR/API 契約檢查（含 fetch 版 SSE 與下載）也已以現行程式碼重跑通過。Windows 的 skips 包含需要 Linux/Docker/PostgreSQL、POSIX 處理程序或平台 symlink 能力的案例；已另在 Linux 執行的部分以上述 Linux 報告為準。Fixture 那組的三個 skips 包含未設定的 PostgreSQL 測試條件及 Windows 專屬路徑；PostgreSQL 情境由另一組補驗。最終政策檢查中的十四項 Docker 整合另行執行，沒有把 skip 當成 pass。2026-10-09 在 G4 第 12–24 輪合併後重驗。第一次執行有 8 項失敗：4 項是 promptfoo／PyRIT 整合測試沒跟上 10-06 的測試輔助函式簽章變更（10-06 那台主機沒有工具映像，這些測試當時為 skip），已修正 tests/test_tool_runners.py；另 4 項是測試主機未佈建離線 OSV 資料，DOCKER_INTEGRATION_TESTING.md 已補上該步驟。修正後整套重跑即為上表收據，詳見 DOCKER_INTEGRATION_TESTING.md 的「2026-10-09 遇到的問題」。

原始逐項名稱、耗時與 skip 原因見 XML；validation-summary.json 由 scripts/summarize-validation.py 自動讀取，沒有用 LLM 補造結果。收據中的主機名與使用者帳號已由 scripts/redact-receipts.py 遮罩（只改 hostname 屬性與家目錄的帳號段，測試、計數、耗時與原因不變）；先前 commit 的版本仍留在 git 歷史中。release-guards.xml、local-pipeline.xml、tool-integration.xml 為較早通過的重疊檢查，不另加計。

docs/history 保留 Schemathesis header 修正前的兩份失敗收據，分別為 25 passed/2 failed 與 4 passed/1 failed；共同原因是範例加入未封存的 header，政策層拒絕後正確保留 inconclusive。修正後結果見上表；不把歷史失敗隱藏成成功。

## 實際驗證的路徑

- 以合成模型契約驅動完整白箱、威脅、需求、案例、真 Docker HTTP 與 PostgreSQL checkpoint/job ledger 流程；另一變體同時執行真 Semgrep、Gitleaks、OSV。合成模型輸出不冒充供應商推理結果。
- PostgreSQL 原子提交與回復、並行 lease claim、journal 恢復與不重複執行。控制處理程序 hard-crash／衍生子處理程序的故障注入使用真 POSIX 處理程序及 process_test 後端；Docker 的實際身分、網路、掛載及正常清理另有整合測試。沒有把處理程序後端故障測試冒充所有 Docker daemon 故障情境；SQLite demo 測試也不代替 PostgreSQL。
- 真容器以非 root 身分及 network=none 執行，黑箱沒有原始碼或 Docker socket；獨立 supervisor 中介目標連線。停止先撤銷通訊，再終止 worker。
- ZAP 2.17.0、Schemathesis 4.28.0、Playwright 1.63.0、promptfoo 0.123.1、PyRIT 1.1.0 使用固定案例與正反例。工具檢查結果不能取代副作用 oracle。
- Semgrep 1.153.0、Gitleaks 8.30.1、OSV-Scanner 2.3.5 使用隨附規則、合成 repository 與完整 PyPI/npm 官方離線資料。資料來源及內容 hash 在 osv-database-manifest.json。
- TypeScript Web fixture 的 BOLA/登出、Python AI fixture 的合成 RAG、工具事件、sink、reset/cleanup。原生 AI fixture 每次五個獨立試驗；外部 AI 工具組合驗收每個正反例各兩次。
- 真 LiteLLM 1.102.1 SDK 配合合成 HTTP transport，涵蓋 OpenAI、OpenAI-compatible、NIM、Anthropic 的成功、redirect、限流及服務錯誤。每次授權限制一次 dispatch，沒有雲端模型流量或費用。
- Desktop 1440px 與 mobile 390px 沒有整頁水平溢出。不可信報告文字沒有被當作 HTML 執行。這不是完整無障礙或跨瀏覽器認證。

## 測試中修正的問題

1. 模型 SDK 的隱性 tokenizer 下載、NIM retry/fallback 行為：改用核對 hash 的隨附資產與單次 dispatch transport。
2. 結果及 journal 分開保存的重播時間窗：改成共同交易提交；送出後未知結果阻擋自動重播。
3. 用量未知仍可恢復呼叫：持久化 unknown usage 並禁止繼續付費模型工作。
4. 白箱路徑競態、symlink/hardlink 及掛載限制：拒絕不安全來源；Linux 使用 descriptor 路徑檢查與 recursive read-only mount。
5. Fixture cleanup 使用與主操作相同的冪等鍵：將 setup、execution、cleanup 分開，確保實際重置與清理各自執行。
6. Windows fixture launcher 退出後仍可能留子處理程序：使用 Job Object 管理處理程序樹，並等待實際監聽埠關閉。
7. 動態工具省略空身分 header；ZAP 使用固定絕對啟動路徑。Schemathesis 範例改用既有案例 header，不放寬未授權 headers。
8. 複測視窗在 findings 載入前初始化：開啟時更新可選項；真瀏覽器驗證成功建立關聯複測。
9. 外部 AI 工具與 fixture lifecycle 組合：執行所選工具並保留 tool receipt，沒有偷偷替換成原生 HTTP。
10. Commander 的派工計畫實際套用（reviewers 並行執行，順序只決定紀錄排列，不影響各自的輸入）；Reporter 只能重排既有 finding IDs，不能補造或升級證據。
11. API 與工作區測試在設定 VIBEAUDIT_DATABASE_URL 時會連到共用的 PostgreSQL，讀到其他測試留下的 runs：這兩個測試模組在每個測試前移除該變數，改用各自 tmp_path 下的 SQLite。
12. SSR/API 契約 smoke 在 Node 24 無法執行：frontend 標記 "type": "module"，以 .ts/.tsx 檔名掛載的虛擬模組會被 Node 24 判定為 ESM；且 App.tsx 的 import.meta.env.DEV 經 transpileModule 後仍殘留（只有 Vite 建置會替換）。改為以 .cjs 檔名掛載轉譯後的 CommonJS，並比照 Vite 建置對 import.meta.env.* 做靜態替換。

## 映像與可重現性

runtime-images.json 保存 provision 時讀出的 image IDs。工具的相依套件先以實際工作映像驗證，再以 deploy/worker/locks 的完整 Python/npm 鎖定檔重建。測試使用的 image ID 及對應報告另見 image-validation.json。 2026-10-07 起 worker 的 Dockerfile 強制 BASE_IMAGE 為 digest，並加上基礎映像標籤；runtime-images.json 中的 worker image ID 早於這次變更，重建 worker 後要重新執行 provision-runtime.py 記錄新的 ID。

固定版本與 hash 提供可追溯輸入，不保證所有 CPU 架構產出完全相同的 image ID。Dockerfile 仍包含作業系統套件安裝，系統套件來源未作完整時間快照；換環境重建必須重新驗收。所有來源、工具、規則、標準和模型分別保留授權。

## 示範與效果比較的界線

sample-report.json / .md 是實際本地合成 demo 的匯出；.md 由 `scripts/render-sample-report.py` 依 .json 以報告產生器輸出中文版與英文版，測試會確認兩者一致。它刻意包含缺少副作用觀測的 inconclusive，整體標為 incomplete；這是驗證「不能假通過」的示例，不表示工程流程沒有執行完。

benchmarks/results-synthetic 有七組、每組六件的 42 次合成比較，用於驗證預算、分組、記錄與指標管線。results-local 的本地 AST 基線實際讀取樣本；沒有模型端點的組別明列 blocked。沒有人工核定的完整 ground truth 與真模型輸出時，正式 efficacy metrics 保持 null，不發布減偏或 recall 改善結論。

已知限制：gold 的 human_reviewed、reviewers 與 oracle_evidence 是宣告欄位，只檢查格式（至少兩個不同姓名、證據清單非空），不能證明審核確實發生。runner 現提供盲審 matching 介面（`python -m vibe_audit.benchmark_matching` 的 worksheet／apply 兩步）：`worksheet` 產生不含組別或模型身分的盲審工作表，兩位具名 reviewer 分別提交裁定檔，一致才回填 gold，分歧需第三位 arbiter 明示裁定；`apply` 回填 gold、重算指標並寫出 matching record 與更新後資料集。工具只記錄裁定宣告，不能證明審核發生；隨附合成資料的 gold 仍標記 synthetic=true，正式 efficacy metrics 維持 null，回填後的 precision 只進入 preview_metrics。正式研究仍須由真人完成審核、保留 reviewer 原始記錄與 oracle 執行證據。

## 尚未驗證或不包含的能力

- 真實三個模型的確切型號、端點、額度、用量與模型品質；使用者自己的 staging 和後端觀測。這些依使用者決定留待配置完成後驗收。
- 任意 repository/framework 的完整語意分析、無限長程式碼、全站探索與主動 fuzz、任意瀏覽器腳本。此版動態工具只執行核准的有限案例。
- promptfoo/PyRIT 的全部上游外掛或任意多步驟紅隊工作流；本版驗證固定受控 target + fixture/effect protocol。
- 跨主機高可用部署、macOS live worker、多人 SaaS、獨立第三方滲透審查或法證級不可竄改儲存。
- 五次未觀測到違規不代表安全；mock 工具與 sink 不證明真實後端授權正確。標準目錄有 462 個 canonical IDs，不等於已測完所有標準。

## 重跑

Windows：安裝後執行 scripts/verify.ps1；Linux 使用 scripts/verify-linux.sh。兩者都會在驗證中本機啟動一個後端處理程序並執行 SSR/API 契約 smoke（預設埠 8002，可用 VIBEAUDIT_SMOKE_PORT 覆寫；Linux 上缺少 node 或 frontend/node_modules 時略過該步並提示）。啟用真整合前設定下列環境變數，值必須來自自己的本地 provisioning：

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

---

# 0.2.1 Local Validation Record

Validation date: 2026-09-24; after follow-up fixes from review, the full Windows regression and the frontend build were re-run on 2026-10-02; after the fixes from the in-depth review were completed on 2026-10-03, the full regression (including PostgreSQL integration and the Node 24 fixture), the frontend type check and production build, and the real API + React SSR contract checks were re-run on WSL2/Linux, and the full Linux regression including all Docker integrations was run with Docker 29.1.3; after the third-round review fixes (controller state reclamation, worker lifecycle teardown and deadline alignment, lease log result/request binding and completed-task reuse, dead-code cleanup, etc., PR #6) were merged on 2026-10-04, both full regression suites, the frontend type check and the production build were re-run on Linux; the Docker integrations covered the isolated worker, the three offline scanners, the five dynamic tools and the full pipeline, and the SSR/API contract checks (including fetch-based SSE and download) were re-run against the current code; on 2026-10-05, after the blind-review matching tool and adjudication-file examples were added, both full Linux regressions, the full Windows regression, the frontend type check and production build, the SSR/API contract and the Edge real-browser checks were re-run, and a fresh-venv install with `--require-hashes` was verified on Windows Python 3.12.10; the same day, after hardening reviewer-name normalization and restricting worksheet rationales to independent phases, all of the above receipts were refreshed again. As specified by the user, this round completed the engineering work and the local integrations that do not require model credentials. **Real Claude, OpenAI or Nemotron were NOT called; no multi-model bias reduction, vulnerability-detection-rate or cost improvement has been demonstrated.**

This round actually used the Windows console, WSL2/Linux, Docker 29.1.3, PostgreSQL 18.6 and eight security tools at pinned versions. The original 2026-09-24 verification host's Windows receipts ran Python 3.12.14; the 2026-10-05 Windows receipts ran Python 3.13.15 (a hash-pinned install was also verified on Windows Python 3.12.10), the Linux test venv used Python 3.14.4, and Node was 24.19.0. The complete Python/npm dependency and tool image lockfiles are delivered with the source code. The images and the offline OSV data themselves are not packed into the ZIP.

## Acceptance Results

The test groups overlap one another; **do not add the rows together and treat the sum as a count of unique tests**. JUnit's successful records include subtests that are reported separately; the table below uses the test counts as displayed by pytest.

| Acceptance | Actual result | Evidence |
|---|---|---|
| Full Linux regression (2026-10-05, current code) | 363 passed, 21 skipped, 4 subtests passed; the PostgreSQL 18.6 integration (atomic rollback, checkpoint and resume, concurrent lease claim) and the Node 24 Web fixture were actually executed; the skips are 20 integrations requiring Docker images and 1 Windows-only case | linux-regression.xml |
| Full Linux regression with Docker integration (2026-10-05, current code) | 383 passed, 1 skipped, 4 subtests passed; the isolated worker, the three offline scanners, the five dynamic tools, the fixture protocol executed with the Docker backend and the full pipeline were all actually executed, and this run also includes the PostgreSQL 18.6 integration and the Node 24 Web fixture; the only skip is Windows-specific. The 10 tests of the blind-review matching tool are also within this receipt's scope | linux-docker-integration.xml |
| Full Linux regression with Docker integration (2026-10-06, current code) | 508 passed, 15 skipped, 4 subtests passed; Python 3.12.3, Docker 29.6.2, PostgreSQL 16.14, Node 24.21.0. The isolated worker, white-box containers without a broker, the fixed black-box http_case sequence, the three offline scanners, the fixture protocol on the Docker backend (including supervisor-record verdicts) and the full pipeline were all actually executed. 14 skips are because this host did not build the tools and ZAP images, so the five dynamic tools were not re-verified this time; the 10-05 receipt stands for them. The remaining skip is Windows-specific | linux-docker-integration-2026-10-06.xml |
| Full Linux regression with Docker integration (2026-10-09, current code) | 559 passed, 1 skipped, 4 subtests passed; Python 3.13.16, Docker 29.8.2, PostgreSQL 16.15, Node 24.21.0. Re-verified after G4 review rounds 12–24 were merged: the isolated worker, the three offline scanners (with offline OSV data), the five dynamic tools, the fixture protocol on the Docker backend and the full pipeline were all actually executed, together with the PostgreSQL integration and the Node 24 Web fixture; the only skip is Windows-specific. Because the build host reaches the internet through an HTTPS proxy, the tools image was rebuilt from the Dockerfile.tools.locked lockfiles with the proxy CA mounted as a BuildKit secret for the install steps only; its image ID differs from runtime-images.json | linux-docker-integration-2026-10-09.xml |
| Full Windows regression (2026-10-05, current code) | 359 passed, 25 skipped, 4 subtests passed | windows-regression.xml |
| PostgreSQL, isolated worker, full workflow | 27 passed, 4 deselected | postgres-pipeline-integration.xml |
| Fixture, reset, stop and failure paths | 24 passed, 3 skipped, 4 subtests passed | runtime-fixture-integration.xml |
| Final workflow and policy checks | 45 passed, 14 skipped | final-guards.xml |
| Dynamic tools and AI lifecycle, fully dependency-locked images | 27 passed; zero failures, zero skips | tool-integration-release.xml |
| Schemathesis header fix | 2 passed, 25 deselected | schemathesis-header-regression.xml |
| Known-issue detection by the three offline scanners | 3 passed | scanner-integration-release.xml |
| Frontend type check and production build (2026-10-05) | Passed, 32 modules; rebuilt with the locked dependencies, the artifacts are byte-identical to frontend/dist | frontend/dist |
| Chromium real browser (2026-10-09, current code) | Playwright 1.49.1 driving Chromium 141 headless: three export types, saving a project, traceability, creating a retest, switching the interface between Chinese and English; 0 page errors, no horizontal overflow. Replaces the 2026-10-05 Edge 154 receipt (kept in git history) | browser-validation.json |
| Real FastAPI + React SSR/API | Three synthetic reviews, fail/pass/inconclusive, seven pieces of evidence, five tabs, three export types and HTML escaping; re-run and passed on 2026-10-05 against the current code (including the evidence adjudication console), also confirming that with only a session cookie /api/session and /api/runs are rejected without leaking the CSRF token, and fetch-based SSE and download were verified with Node | api-ssr-validation.json |
| Mutation testing (2026-10-10, current code) | mutmut 3.8.0 generated 4,620 mutants of `policy.py`, `adapters.py`, `catalog.py`, `lease.py`, `snapshot.py` and `messages.py` and ran the unit suites against each (lease tests on PostgreSQL included). The third round read every surviving mutant's diff: an observable difference got a precise assertion (whole messages, every limit boundary, optional fields read by their exact names, reads under the PostgreSQL row lock, the full content of observations and evidence), an equivalent mutant a `# pragma: no mutate` with its reason. Result: 4,546 caught, 73 escaped (one timeout not counted). What remains sits in `adapters.py` 36, `policy.py` 14, `snapshot.py` 12, `lease.py` 8 and `catalog.py` 3; `messages.py` 0, nearly all equivalent (a lower-case default before `.upper()`, a missing-key default another check already refuses, a platform constant that is 0 on Linux, a json argument that reads None as False). These are the per-module ceilings in `tests/mutation-baseline.json` (each function's count is recorded too, for a pull request's `--changed` run), down from 1,301 after the first round and 623 after the second; only more tests lower them. A full run always starts from an empty `mutants/` (the script clears it): mutmut reuses the old result of a mutant whose text is unchanged, so new tests would never meet it. | Local `scripts/mutation-test.py` log; `.github/workflows/mutation.yml` is off by default (re-runs weekly only with the repository variable `VIBEAUDIT_MUTATION=true`; a manual dispatch always runs) |
| Python dependency consistency | pip check passed; after the lockfile carried hashes (2026-10-03; re-run 2026-10-04), installation with `--require-hashes` into fresh venvs passed: the packages actually installed on Linux Python 3.14.4, Windows Python 3.13.15 and Windows Python 3.12.10 (2026-10-05) match the lockfile item by item, and that Linux venv, excluding Docker, tested 350 passed, 21 skipped | requirements.lock.txt |

The two full Linux regressions (with and without Docker integration), the frontend build, the SSR/API contract and the full Windows regression all represent the current code as of 2026-10-05. On 2026-10-06, after the fixes from G4 review rounds 5–11 were merged, the full Linux regression with Docker integration was re-verified separately; the failures before that receipt was obtained and their causes are in "Problems encountered on 2026-10-06" in DOCKER_INTEGRATION_TESTING.md. The remaining rows are results from 2026-09-24. After the 10-03 fixes (session protocol, supervisor failure classification, staging lifecycle, etc.) and the 10-04 fixes (unified supervisor teardown, controller deadline alignment, log reuse, guardian transient-error tolerance, etc.), the isolated worker, scanner and dynamic tool integrations have been re-verified by linux-docker-integration.xml; the itemized 09-24 receipts in the table are kept as records of that time. Several runs before the 10-03 receipts were obtained had failures: four were cases where the tests themselves depended on external environment variables (fixed, see item 11 below), and the rest came from incomplete environment variable and runtime profile configuration on the test host; see DOCKER_INTEGRATION_TESTING.md for details. The Edge real-browser checks were re-run on 10-05 against the current code and passed (frontend/scripts/browser-smoke.cjs with the system Edge 154 headless); the SSR/API contract checks (including fetch-based SSE and download) have also been re-run and passed against the current code. The Windows skips include cases requiring Linux/Docker/PostgreSQL, POSIX processes or platform symlink capability; for the parts also executed on Linux, the Linux reports above take precedence. The three skips in the fixture group include an unconfigured PostgreSQL test condition and Windows-specific paths; the PostgreSQL scenario is covered by a separate group. The fourteen Docker integrations in the final policy checks were executed separately; skips were never counted as passes. On 2026-10-09, after G4 review rounds 12–24 were merged, the suite was re-verified. The first run had 8 failures: 4 promptfoo/PyRIT integration tests had not followed a test-helper signature change from 10-06 (the 10-06 host had no tools image, so they were skipped then), fixed in tests/test_tool_runners.py; the other 4 came from a test host without offline OSV data, and DOCKER_INTEGRATION_TESTING.md now includes that step. The whole suite was then re-run for the receipt in the table; see "Problems encountered on 2026-10-09" in DOCKER_INTEGRATION_TESTING.md.

The original per-test names, durations and skip reasons are in the XML; validation-summary.json is read automatically by scripts/summarize-validation.py, and no LLM was used to fabricate results. Hostnames and user accounts in the receipts have been redacted by scripts/redact-receipts.py (only the hostname attributes and the account segments of home directories are changed; the tests, counts, durations and reasons are unchanged); previously committed versions remain in git history. release-guards.xml, local-pipeline.xml and tool-integration.xml are earlier overlapping checks that passed and are not counted additionally.

docs/history keeps the two failed receipts from before the Schemathesis header fix, 25 passed/2 failed and 4 passed/1 failed respectively; the common cause was that examples added unsealed headers, and after the policy layer rejected them, inconclusive was correctly preserved. The post-fix results are in the table above; historical failures are not hidden as successes.

## Paths Actually Verified

- Synthetic model contracts drove the full white-box, threat, requirement, case, real Docker HTTP and PostgreSQL checkpoint/job ledger flows; another variant also ran real Semgrep, Gitleaks and OSV. Synthetic model output does not impersonate vendor inference results.
- PostgreSQL atomic commit rollback, concurrent lease claims, journal recovery and non-duplicate execution. Fault injection for control-process hard crashes and spawned child processes used real POSIX processes and the process_test backend; Docker's actual identity, network, mounts and normal cleanup have separate integration tests. The process-backend fault tests are not passed off as covering all Docker daemon failure scenarios; the SQLite demo tests also do not substitute for PostgreSQL.
- Real containers ran as non-root with network=none; the black box had no source code or Docker socket; an independent supervisor mediated target connections. Stopping first revokes communication, then terminates the worker.
- ZAP 2.17.0, Schemathesis 4.28.0, Playwright 1.63.0, promptfoo 0.123.1 and PyRIT 1.1.0 used fixed cases with positive and negative examples. Tool check results cannot replace side-effect oracles.
- Semgrep 1.153.0, Gitleaks 8.30.1 and OSV-Scanner 2.3.5 used bundled rules, a synthetic repository and the complete official PyPI/npm offline data. Data sources and content hashes are in osv-database-manifest.json.
- The TypeScript Web fixture's BOLA/logout; the Python AI fixture's synthetic RAG, tool events, sink and reset/cleanup. The native AI fixture used five independent trials each time; the external AI tool combination acceptance ran each positive and negative example twice.
- The real LiteLLM 1.102.1 SDK with a synthetic HTTP transport covered success, redirect, rate-limiting and service errors for OpenAI, OpenAI-compatible, NIM and Anthropic. One dispatch per authorization constraint; there was no cloud model traffic or cost.
- Desktop 1440px and mobile 390px had no full-page horizontal overflow. Untrusted report text was not executed as HTML. This is not full accessibility or cross-browser certification.

## Issues Fixed During Testing

1. Implicit tokenizer downloads by model SDKs and NIM retry/fallback behavior: switched to hash-verified bundled assets and a single-dispatch transport.
2. A replay window from results and journal being saved separately: changed to joint transaction commits; unknown outcomes after submission block automatic replay.
3. Calls could still resume with unknown usage: unknown usage is now persisted and further paid-model work is forbidden.
4. White-box path races, symlink/hardlink and mount restrictions: unsafe sources are rejected; Linux uses descriptor path checks and recursive read-only mounts.
5. Fixture cleanup used the same idempotency key as the main operation: setup, execution and cleanup are now separated, ensuring the actual reset and cleanup each run.
6. The Windows fixture launcher could leave child processes behind after exiting: a Job Object now manages the process tree, and the code waits for the actual listening port to close.
7. Dynamic tools omitted empty identity headers; ZAP uses a fixed absolute launch path. Schemathesis examples now use existing case headers, without loosening the unauthorized headers.
8. The retest window was initialized before findings were loaded: options are refreshed when it opens; real-browser verification successfully created a linked retest.
9. Combining external AI tools with the fixture lifecycle: the selected tools are executed and the tool receipt is kept, without silently substituting native HTTP.
10. The Commander's dispatch plan is actually applied (reviewers run in parallel; ordering only determines the arrangement of records and does not affect their individual inputs); the Reporter can only reorder existing finding IDs and cannot fabricate or upgrade evidence.
11. When VIBEAUDIT_DATABASE_URL was set, the API and workspace tests would connect to the shared PostgreSQL and read runs left by other tests: these two test modules now remove that variable before each test and use SQLite under their own tmp_path.
12. The SSR/API contract smoke stopped working under Node 24: the frontend package is marked "type": "module", so virtual modules mounted with .ts/.tsx filenames are loaded as ESM by Node 24; moreover App.tsx's import.meta.env.DEV survives transpileModule (only the Vite build replaces it). The smoke now mounts the transpiled CommonJS as .cjs and applies the same static import.meta.env.* substitution as the Vite build.

## Images and Reproducibility

runtime-images.json stores the image IDs read at provision time. Tool dependencies were first verified against the actual working images, then rebuilt with the complete Python/npm lockfiles under deploy/worker/locks. The image IDs used in testing and the corresponding reports are in image-validation.json. Since 2026-10-07 the worker Dockerfile requires a digest BASE_IMAGE and adds a base-image label; the worker image ID in runtime-images.json predates that change, so after rebuilding the worker re-run provision-runtime.py to record the new ID.

Pinned versions and hashes provide traceable inputs and do not guarantee that all CPU architectures produce identical image IDs. The Dockerfile still includes operating system package installation, and the system package sources were not fully time-snapshotted; rebuilding in a different environment requires re-acceptance. All sources, tools, rules, standards and models retain their respective licenses.

## Boundaries of the Demo and Effect Comparison

sample-report.json / .md are exports of an actual local synthetic demo; `scripts/render-sample-report.py` renders the .md from the .json with the report generator, Chinese then English, and a test keeps them in step. It deliberately includes inconclusive entries that lack side-effect observations and is marked incomplete overall; this is an example demonstrating that "passing cannot be faked", not an indication that the engineering flow failed to run to completion.

benchmarks/results-synthetic contains seven groups of six items each — 42 synthetic comparisons in total — used to verify the budget, grouping, recording and metric pipelines. The local AST baseline in results-local actually reads samples; groups without model endpoints are explicitly listed as blocked. Without a manually adjudicated complete ground truth and real model outputs, the official efficacy metrics remain null and no bias-reduction or recall-improvement conclusions are published.

Known limitation: the gold's human_reviewed, reviewers and oracle_evidence are declarative fields, only format-checked (at least two distinct names, a non-empty evidence list), and cannot prove that review actually happened. The runner now provides a blind-review matching interface (the worksheet/apply steps of `python -m vibe_audit.benchmark_matching`): `worksheet` produces a blinded review worksheet without arm or model identity; two named reviewers submit separate adjudication files, gold is backfilled only when their verdicts agree, and disagreements require an explicit third arbiter; `apply` backfills the gold, recomputes the metrics, and writes the matching record and updated dataset. The tool records adjudication declarations only — it cannot prove that review happened; the bundled synthetic gold remains synthetic=true, so the formal efficacy metrics stay null and the backfilled precision enters preview_metrics only. A formal study still requires real humans to perform the review and to retain the reviewers' original records and oracle execution evidence.

## Capabilities Not Yet Verified or Not Included

- The exact model names, endpoints, quotas, usage and model quality of the three real models; the user's own staging and backend observations. At the user's decision, these are left for acceptance after configuration is complete.
- Full semantic analysis of arbitrary repositories/frameworks, unbounded code length, full-site exploration and active fuzzing, and arbitrary browser scripting. The dynamic tools in this version only execute the approved, limited cases.
- All upstream plugins of promptfoo/PyRIT or arbitrary multi-step red-team workflows; this version verifies a fixed, controlled target + fixture/effect protocol.
- Cross-host high-availability deployment, macOS live workers, multi-user SaaS, independent third-party penetration review, or forensic-grade tamper-proof storage.
- Five trials with no observed violations do not mean safety; mock tools and sinks do not prove that real backend authorization is correct. The standards catalog has 462 canonical IDs, which is not the same as having tested all standards.

## Re-running

Windows: run scripts/verify.ps1 after installation; Linux uses scripts/verify-linux.sh. Both start a local backend process and run the SSR/API contract smoke during verification (default port 8002, override with VIBEAUDIT_SMOKE_PORT; on Linux the step is skipped with a notice when node or frontend/node_modules is missing). Before enabling the real integrations, set the following environment variables; the values must come from your own local provisioning:

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

verify-linux.sh only writes JUnit receipts when `VIBEAUDIT_JUNIT_XML` is set; run `python scripts/redact-receipts.py` before placing them in docs/. Without PostgreSQL administrator rights, you can use the installed `initdb` and `pg_ctl` to start, as an ordinary user and in a temporary directory, a test instance listening only on a unix socket (for example `-o "-k /tmp/pgsock -p 55432 -c listen_addresses=''"`), then point the URL above at it; the 2026-10-03 Linux receipt was obtained this way. The web fixture tests specify Node 24 via `VIBEAUDIT_TEST_NODE`. The flags required by the other integration tests follow the explicit skip conditions in each tests/test_*.py; the exception is that when VIBEAUDIT_FIXTURE_IMAGE is not set, the fixture protocol tests fall back to the process_test backend and do not show up as skips. For the steps to run the whole tests/ (including the Docker integrations) under an ordinary user account, and for common configuration mistakes such as the runtime profile's work_root needing to be writable, see DOCKER_INTEGRATION_TESTING.md. For complete Linux provisioning, the credential reference, fixtures, scope and database setup, see LINUX_SETUP.md. The environment variables for the browser smoke are in frontend/scripts/browser-smoke.cjs; for SSR specify `node frontend/scripts/contract-smoke.mjs --base-url http://127.0.0.1:8002`. For a different port, substitute your own loopback console.
