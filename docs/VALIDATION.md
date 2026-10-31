# 0.2.1 本地驗證紀錄

驗證日期：2026-09-24；審查後續修正後於 2026-10-02 重跑 Windows 全套回歸與前端建置；2026-10-03 深入審查的修正完成後，在 WSL2/Linux 重跑全套回歸（含 PostgreSQL 整合與 Node 24 fixture）、前端型別檢查與 production build、真 API + React SSR 契約檢查，並以 Docker 29.1.3 執行含全部 Docker 整合的 Linux 全套回歸；2026-10-04 第三輪審查修正（controller 狀態回收、worker 生命週期 teardown 與期限對齊、lease 日誌 result/request 綁定與已完成任務重用、死碼清理等，PR #6）合併後，在 Linux 重跑兩份全套回歸、前端型別檢查與 production build，Docker 整合包含隔離 worker、三種離線掃描器、五種動態工具與完整 pipeline，並以現行程式碼重跑 SSR/API 契約檢查（含 fetch 版 SSE 與下載）；2026-10-05 加入盲審 matching 工具與裁定檔範例後，重跑兩份 Linux 全套回歸、Windows 全套回歸、前端型別檢查與 production build、SSR/API 契約與 Edge 真實瀏覽器檢查，並在 Windows Python 3.12.10 以 `--require-hashes` 驗證全新 venv 安裝；同日完成 reviewer 名稱正規化與 worksheet 理由只取獨立階段的安全強化後，上述全部收據再次更新。依使用者指定，本次完成工程及不需要模型憑證的本地整合。**以上 09-24～10-05 的驗證未呼叫真實 Claude、OpenAI 或 Nemotron；10-10～11 的真模型整合另見下節。仍未證明多模型減偏、漏洞檢出率或成本改善。**

本次已實際使用 Windows 控制台、WSL2/Linux、Docker 29.1.3、PostgreSQL 18.6 及固定版本的八種安全工具。09-24 原始驗證主機的 Windows 收據為 Python 3.12.14；10-05 的 Windows 收據為 Python 3.13.15（另以 Windows Python 3.12.10 驗證雜湊鎖定安裝），Linux 測試 venv 為 Python 3.14.4，Node 為 24.19.0。完整 Python/npm 相依套件與工具映像鎖定檔隨原始碼交付。映像與離線 OSV 資料本身不放進 ZIP。

## 2026-10-11 備援模型與不遮蔽測試字面值的驗收

PR #44 加入兩項功能：操作者設定的備援模型（`fallback`），以及不遮蔽的合成測試憑證（`unredacted_literals`）。接著以真模型跑了 #18～#26。模型、環境與限制都和上一節相同；每次 run 的資料也已補進 real-model-acceptance-2026-10-11.json。這 9 次共約 172 萬 tokens，26 次合計約 383 萬 tokens。

| run | 靶場與設定 | 結果 |
|---|---|---|
| #18 | AI agent vulnerable；Gemini 3.8 Flash 審查員，本地 Qwen 3.8 27B 當它的備援 | Gemini 拒答，改問備援；但 Qwen 在 16,000 輸出 token 處被截斷，run 停在白箱 |
| #19 | 同 #18，Qwen 輸出上限改為 32,768 | 跑完全程；原生、promptfoo、PyRIT 三個案例都 fail（可信 ledger 記錄到未授權的匯出）。Gemini 這次有回答，備援沒用上；Nemotron 被截斷，恢復一次 |
| #20 | Web API vulnerable；操作者案例 BOLA、登出；宣告 `fixture-web-a`、`fixture-web-b` | 封存的快照裡，這兩個 session 值原樣保留，沒宣告的密碼仍遮蔽，第一項缺口記下「2 of 2」。Gemini 拒答，沒有備援，run 停在白箱 |
| #21 | 同 #20，加上本地 Qwen 備援 | 跑完全程；BOLA 與登出都 fail。審查員不再回報 session token 被遮蔽：#14 時 Claude 因此無法確認登出刪除的是哪個 token。威脅模型違反參照規則一次，恢復後通過 |
| #22 | 同 #21 | Gemini 拒答，本地 Qwen 完整代答。審查結果記下 `answered_by` 與 qwen 家族，白箱的家族多樣性閘門通過。之後跑完全程，BOLA 與登出都 fail |
| #23 | 同 #22，Qwen 也當威脅建模員的備援 | Gemini 再次拒答，Qwen 再次完整代答，家族閘門通過。威脅建模員沒有拒答，在寫明資料流規則的程式上第一次就通過，所以它的備援沒用上。沒有恢復就跑完全程，BOLA 與登出都 fail |
| #24 | 同 #23，主機重開後重建的環境 | Gemini 拒答，Qwen 完整代答，家族閘門通過。威脅建模員沒有拒答，第一次就通過。Nemotron 截斷兩次，SSO 登入過期一次，恢復三次後跑完全程，BOLA 與登出都 fail |
| #25 | 同 #24 | 同 #24：Gemini 拒答、Qwen 代答，威脅建模員沒有拒答。Nemotron 截斷一次，恢復後跑完全程，BOLA 與登出都 fail |
| #26 | 同 #24 | 同 #24：Gemini 拒答、Qwen 代答，威脅建模員沒有拒答。沒有恢復就跑完全程，BOLA 與登出都 fail |

- **#18 找到的問題（PR #44 已修正）**：
  - 原本備援還沒回答就先記成「已代答」，所以 #18 的能力限制那一行是錯的。現在改成先記「改問備援」，等備援真的回答後才記為代答。
  - 備援也失敗時，錯誤現在寫明是哪個備援失敗。
- **備援代答已驗證（#22）**：Gemini 拒答，本地 Qwen 回答整份審查，能力限制記下這次代答，家族閘門檢查的是 Qwen。兩個本地模型同時回答、共用硬體時，每個約每秒 10 tokens，白箱用了約 25 分鐘。
- **威脅建模員的備援尚未用上**：#23～#26 這 4 次都為威脅建模員設了備援，但它都沒有拒答，每次都第一次就通過，所以「威脅建模員拒答時由備援寫完威脅模型」還沒在真模型上看到。這條路徑目前只有單元測試涵蓋。
- **#24～#26 的環境**：主機重開後，資料庫、靶場、離線 OSV 資料、runtime 設定與控制台都重新建立，run 設定依 #23 的紀錄與靶場 README 重寫。登出案例 C-LOGOUT、兩條操作者需求，以及指揮官與威脅建模員的輸出上限（16,000）可能和 #23 不同。
  - LM Studio 重開後，Nemotron 在收到請求時才自動載入，上下文只有 8,192，所以 #24 第一次恢復時又被截斷；以 71,936 重新載入後才通過。本地模型的上下文要在跑之前確認。
  - #24 第一次嘗試時 LM Studio 還連不上，在預檢就失敗；那筆資料隨舊資料庫清掉，沒有列入。
- **威脅模型的資料流規則**：#17、#21、#22 都在同一條規則上失敗：資料流指向沒有宣告的資產，因為契約沒有說呼叫者和攻擊者也要列成資產。現在 schema 說明、威脅建模指示與重試提示都寫明這一點，#22 在這份程式碼上恢復後通過。中間有一次是威脅建模員（Sonnet）拒答；#22 只為 Gemini 審查員設了備援，所以那次靠恢復處理。

## 2026-10-10～11 真模型驗收

第一次以真實模型跑完整流程。目標只有本 repo 的合成靶場，不代表模型的效果、檢出率或成本表現。每次 run 的設定、各階段結果與用量，記在 real-model-acceptance-2026-10-11.json。

- **模型**：
  - 指揮官（兼反證與架構）：Claude Opus 5.5（AWS Bedrock，以 SSO profile 簽章）。
  - 審查員：Gemini 3.8 Flash（Google，OpenAI 相容端點）、Claude Sonnet 5.5（Bedrock）、Nemotron 3 Super（本機 LM Studio，json_schema 模式，context 71,936）。AI agent 靶場改用 Gemma 4 31B（Gemini API）取代 Gemini。
  - 威脅建模：最後改用 Claude Sonnet 5.5。
  - 測試設計：Gemini 3.8 Flash。
- **環境**：PostgreSQL 18.6、Docker 29.1.3、隔離 worker；#11 起加上 Semgrep 1.153.0、Gitleaks 8.30.1、OSV-Scanner 2.3.5（離線 PyPI／npm 資料），以及 promptfoo 0.124.1、PyRIT 1.1.0 的 tools 映像。
- **結果**：17 次 run，共約 211 萬 tokens。其中 5 次跑完全程，預期結果都成立：

| run | 靶場 | 案例 | 黑箱結果 |
|---|---|---|---|
| #6、#8 | Web API vulnerable | 模型設計的 BOLA | fail（觀測到 tenant B 的 canary） |
| #13 | Web API fixed | 模型設計的 BOLA | pass（真陰性，沒有誤報） |
| #14 | Web API vulnerable，三種掃描器 | 操作者案例：BOLA、登出 | 兩者都 fail；登出後同一 session 仍可讀取 |
| #17 | AI agent vulnerable，三種掃描器 | 操作者案例：原生 ×5、promptfoo ×2、PyRIT ×2 | 三者都 fail；可信 ledger 記錄到未授權的匯出 |

- **其他 12 次 run**：都是在途中發現問題後停下，問題已逐一修正（PR #40～#43）：
  - LiteLLM 把呼叫參數放進請求本文。
  - LM Studio 只接受 json_schema 格式。
  - 本地推理模型逾時，或探測、輸出被截斷。
  - Gemini 偶發 HTTP 500 與內容過濾。
  - 模型抄錯 UUID。
  - 威脅模型違反參照規則。
  - 模型案例無法涵蓋的威脅被標為 automated。
  - Gemma 不接受 maxItems。
  - 4xx 拒絕被當成用量不明。
  - 操作者自己的案例設定錯誤：被 gate 正確擋下。
- **還沒解決**：雲端模型在撰寫攻擊情境或審查提示注入程式碼時會不定期拒答：Gemini 在 #10、#12，Claude Opus 在 #5。拒答會留下明確紀錄、run 可恢復，但同一個模型通常還是拒答。之後加入了操作者設定的備援模型（`fallback` 角色）：指定的 Agent 拒答或被截斷時由它代答，並記在報告裡。

## 2026-10-10 深入審查修正

這一輪修正了一次全面審查找到的問題（PR #39，分支 fix/deep-review-2026-10-10，已合併 main 到 c2a027f）。

- 這一輪重跑的：
  - Linux 全套回歸：1254 passed、22 skipped、4 subtests passed（linux-regression-2026-10-10.xml）。環境是 Python 3.12.15、PostgreSQL 18.6（CI 釘選的 digest）、Node 24.21.0。
  - 以真 Docker 執行的隔離測試：88 passed、1 skipped、4 subtests passed（docker-isolation-2026-10-10.xml）。環境是 Docker 29.1.3；worker 映像以 CI 使用的 python digest 建置。
  - 前端：型別檢查、vitest、i18n 與訊息表檢查、production build 都通過。
  - ruff：通過。
  - 依賴稽核：以釘選的 osv-scanner 檢查 requirements.lock.txt 與 frontend/package-lock.json，沒有已知漏洞。
- 這一輪沒有在本機重跑的：
  - 三種離線掃描器、五種動態工具、完整 pipeline：這台主機沒有這些映像，改由 integration.yml 在 CI 上執行。
  - Windows 回歸與 Edge 真實瀏覽器檢查。
- 已知、尚未處理：deploy/worker/locks 的工具映像依賴有 14 筆已知漏洞，分布在 11 個套件（osv.dev 2026-10-10）。它們來自 promptfoo 0.123.1 與 PyRIT 的相依套件，例如 simple-git、basic-ftp、sharp、werkzeug，其中幾筆在上游還沒有修正版。要處理必須更新工具版本、重建 tools 映像並重新驗收，所以這一輪沒有改動。這是 10-10 的歷史缺口；現行 dependency-drift.py 已涵蓋工具映像的兩個鎖定檔。
- 修正內容（詳見 git log）：
  - supervisor 啟動後，controller 端的任何失敗都回報 outcome_unknown。
  - worker 回傳格式錯誤時，supervisor 已記錄的外洩仍判 fail。
  - supervisor 丟棄 worker 自行宣告的 supervisor 欄位。
  - runtime profile 不能選用 process_test。
  - broker 請求設有整體期限。
  - lease 期限涵蓋 supervisor 啟動、容器建立與 teardown，worker 本身的時限由 supervisor 強制。
  - 送出封存的 body 位元組。
  - 拒絕 NAT64／6to4 形式的 metadata 位址。
  - Docker API 版本改為協商。
  - OSV 只採用已驗證的生態系，exit 128 記為缺口。
  - positive control 合約與執行器一致。
  - 模型 payload 依上限裁切。
  - 預算拒絕以原因呈現。
  - 合約檢查併入有界重試。
  - 複測只帶入相關案例，結果寫回上層發現。
  - 待核准的案例可以退回。
  - 恢復時重用已付費的模型答案。
  - 控制台的錯誤顯示、輪詢退避與無障礙。

## 驗收結果

測試組互有重疊，**不可將各列相加當作不重複測試數**。JUnit 的 successful records 包含另外輸出的 subtests；下表使用 pytest 顯示的測試數。

| 驗收 | 實際結果 | 證據 |
|---|---|---|
| 備援模型與不遮蔽測試字面值（2026-10-11） | 9 次 run；#19、#21～#26 跑完全程，vulnerable 靶場都 fail；宣告的測試 session 在快照中未遮蔽；#22～#26 由備援完整代答審查，家族閘門通過；威脅建模員 4 次都沒有拒答，它的備援尚未用上 | real-model-acceptance-2026-10-11.json |
| 真模型完整流程（2026-10-10～11） | 17 次 run；5 次跑完全程，vulnerable 靶場都 fail（BOLA、登出、AI agent 未授權匯出），fixed 靶場 pass | real-model-acceptance-2026-10-11.json |
| Linux 全套回歸（2026-10-10，本輪修正後） | 1254 passed、22 skipped、4 subtests passed；PostgreSQL 18.6 與 Node 24 實際執行 | linux-regression-2026-10-10.xml |
| 真 Docker 隔離測試（2026-10-10，本輪修正後） | 88 passed、1 skipped、4 subtests passed；Docker 29.1.3 | docker-isolation-2026-10-10.xml |
| Linux 全套回歸（2026-10-05，當時程式碼） | 363 passed、21 skipped、4 subtests passed；PostgreSQL 18.6 整合（原子回復、checkpoint 與 resume、lease 並行 claim）與 Node 24 Web fixture 皆實際執行；skips 為 20 項需要 Docker 映像的整合及 1 項 Windows 專屬 | linux-regression.xml |
| Linux 全套回歸含 Docker 整合（2026-10-05，當時程式碼） | 383 passed、1 skipped、4 subtests passed；隔離 worker、三種離線掃描器、五種動態工具、以 Docker 後端執行的 fixture protocol 與完整 pipeline 皆實際執行，另含 PostgreSQL 18.6 整合與 Node 24 Web fixture；唯一的 skip 為 Windows 專屬。盲審 matching 工具的 10 項測試也在此收據範圍內 | linux-docker-integration.xml |
| Linux 全套回歸含 Docker 整合（2026-10-06，當時程式碼） | 508 passed、15 skipped、4 subtests passed；Python 3.12.3、Docker 29.6.2、PostgreSQL 16.14、Node 24.21.0。隔離 worker、白箱容器不掛 broker、黑箱 http_case 固定序列、三種離線掃描器、以 Docker 後端執行的 fixture protocol（含 supervisor 紀錄判定）與完整 pipeline 皆實際執行。14 項 skip 是這台主機沒有建置 tools 與 ZAP 映像，所以五種動態工具這次沒有重驗，以 10-05 收據為準；另 1 項為 Windows 專屬 | linux-docker-integration-2026-10-06.xml |
| Linux 全套回歸含 Docker 整合（2026-10-09，當時程式碼） | 559 passed、1 skipped、4 subtests passed；Python 3.13.16、Docker 29.8.2、PostgreSQL 16.15、Node 24.21.0。G4 第 12–24 輪合併後重驗：隔離 worker、三種離線掃描器（含離線 OSV 資料）、五種動態工具、以 Docker 後端執行的 fixture protocol 與完整 pipeline 皆實際執行，另含 PostgreSQL 整合與 Node 24 Web fixture；唯一的 skip 為 Windows 專屬。工具映像因建置環境的 HTTPS 代理，以 BuildKit secret 掛載代理 CA 只供安裝步驟使用後由 Dockerfile.tools.locked 的鎖定檔重建，image ID 與 runtime-images.json 不同 | linux-docker-integration-2026-10-09.xml |
| Windows 全套回歸（2026-10-05，當時程式碼） | 359 passed、25 skipped、4 subtests passed | windows-regression.xml |
| PostgreSQL、隔離 worker、完整工作流 | 27 passed、4 deselected | postgres-pipeline-integration.xml |
| Fixture、重置、停止與故障路徑 | 24 passed、3 skipped、4 subtests passed | runtime-fixture-integration.xml |
| 最終流程與政策檢查 | 45 passed、14 skipped | final-guards.xml |
| 動態工具及 AI lifecycle、完整相依套件鎖定映像 | 27 passed；零失敗、零跳過 | tool-integration-release.xml |
| Schemathesis header 修正 | 2 passed、25 deselected | schemathesis-header-regression.xml |
| 三種離線掃描器的已知問題偵測 | 3 passed | scanner-integration-release.xml |
| 前端型別檢查及 production build（2026-10-05） | 通過，32 modules；以鎖定的相依套件重建，產物與 frontend/dist 逐位元組相同 | frontend/dist |
| Chromium 真實瀏覽器（2026-10-09，當時程式碼） | Playwright 1.49.1 驅動 Chromium 141 headless：三種匯出、保存專案、追溯、建立複測、中英介面切換；0 page errors、無水平溢位。取代 2026-10-05 的 Edge 154 收據（保留在 git 歷史） | browser-validation.json |
| 真 FastAPI + React SSR/API | 三份合成審查、fail/pass/inconclusive、七份證據、五分頁、三種匯出及 HTML 跳脫；2026-10-05 以現行程式碼重跑通過（含證據裁決控制台），另確認只帶 session cookie 時 /api/session 與 /api/runs 拒絕且不洩漏 CSRF token，並以 Node 驗證 fetch 版 SSE 與下載 | api-ssr-validation.json |
| 突變測試（2026-10-10，當時程式碼） | mutmut 3.8.0 對 `policy.py`、`adapters.py`、`catalog.py`、`lease.py`、`snapshot.py`、`messages.py` 產生 4,620 個突變，以單元測試套件逐一測試（lease 測試含 PostgreSQL）。第三輪逐一讀過每個存活突變的 diff：可觀測的差異補精確斷言（整句訊息、每個邊界值、以欄位確切名稱讀取的選用欄位、PostgreSQL 列鎖下的讀取、觀測與證據的完整內容），等價的標 `# pragma: no mutate` 並附一句理由。結果：抓到 4,546、逃過 73（1 個逾時不計）。剩下的在 `adapters.py` 36、`policy.py` 14、`snapshot.py` 12、`lease.py` 8、`catalog.py` 3；`messages.py` 0，幾乎都是等價突變（`.upper()` 之前的小寫預設、別處已擋下的缺鍵預設、Linux 上為 0 的平台常數、`None` 讀作 False 的 json 參數）。這些數字是 `tests/mutation-baseline.json` 的各模組上限（另記每個函式的數字供 pull request 的 `--changed` 使用），由第一輪的 1,301、第二輪的 623 降下來；只有補測試才能再降。完整跑一律從空的 `mutants/` 開始（腳本自行清除）：mutmut 會沿用文字未變的突變的舊結果，不讓新測試碰到它們。 | 本機 `scripts/mutation-test.py` 執行紀錄；`.github/workflows/mutation.yml` 預設關閉（repository variable `VIBEAUDIT_MUTATION=true` 才每週重跑，手動 dispatch 一律跑） |
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

- 新增模型型號、端點與環境的個別驗收，以及真實模型的正式品質與成本比較；使用者自己的 staging 和後端觀測。既有 26 次真模型與合成靶場整合紀錄不代替這些驗收。
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

## 2026-10-31 審查修正與可重現驗證

本輪修正發現與威脅的明確追溯、複測範圍、完整反證涵蓋條件、未知模型計費、案例設計完整允許清單，以及有界分批閱讀。動態驗證不再直接推定高風險；未提供嚴重度時標示尚未評級。控制台顯示已納入的文字量與每位審查員完成的批次，不把納入範圍當成完整儲存庫涵蓋率。

本輪測試使用獨立暫存 PostgreSQL 與既有釘選 Docker 映像，模型呼叫採合成契約；未使用真實金鑰，未執行新的付費模型或效果實驗。新增回歸在修正前為 14 failed、1 passed，證明原問題確實可被捕捉。最終通過收據、環境與原始碼輸入雜湊列於 review-validation-2026-10-31.json；其 source_inputs_sha256 排除文件與產生檔，避免收據自我雜湊循環。驗證紀錄是本機證據，不能代替獨立簽章或鑑識級儲存。

舊收據只代表其執行當時版本。三模型的歷史整合驗收與正式效果比較分開：前者已有 26 次真模型搭配合成靶場紀錄，後者仍未完成。任意框架完整語意分析、真實目標的後端觀測與獨立研究資料集仍屬外部驗收，不以此次回歸冒充完成。

---

# 0.2.1 Local Validation Record

Validation date: 2026-09-24; after follow-up fixes from review, the full Windows regression and the frontend build were re-run on 2026-10-02; after the fixes from the in-depth review were completed on 2026-10-03, the full regression (including PostgreSQL integration and the Node 24 fixture), the frontend type check and production build, and the real API + React SSR contract checks were re-run on WSL2/Linux, and the full Linux regression including all Docker integrations was run with Docker 29.1.3; after the third-round review fixes (controller state reclamation, worker lifecycle teardown and deadline alignment, lease log result/request binding and completed-task reuse, dead-code cleanup, etc., PR #6) were merged on 2026-10-04, both full regression suites, the frontend type check and the production build were re-run on Linux; the Docker integrations covered the isolated worker, the three offline scanners, the five dynamic tools and the full pipeline, and the SSR/API contract checks (including fetch-based SSE and download) were re-run against the current code; on 2026-10-05, after the blind-review matching tool and adjudication-file examples were added, both full Linux regressions, the full Windows regression, the frontend type check and production build, the SSR/API contract and the Edge real-browser checks were re-run, and a fresh-venv install with `--require-hashes` was verified on Windows Python 3.12.10; the same day, after hardening reviewer-name normalization and restricting worksheet rationales to independent phases, all of the above receipts were refreshed again. As specified by the user, this round completed the engineering work and the local integrations that do not require model credentials. **The 09-24 through 10-05 checks above did not call real Claude, OpenAI or Nemotron; real-model integration on 10-10 through 10-11 is recorded below. No multi-model bias reduction, vulnerability-detection-rate or cost improvement has been demonstrated.**

This round actually used the Windows console, WSL2/Linux, Docker 29.1.3, PostgreSQL 18.6 and eight security tools at pinned versions. The original 2026-09-24 verification host's Windows receipts ran Python 3.12.14; the 2026-10-05 Windows receipts ran Python 3.13.15 (a hash-pinned install was also verified on Windows Python 3.12.10), the Linux test venv used Python 3.14.4, and Node was 24.19.0. The complete Python/npm dependency and tool image lockfiles are delivered with the source code. The images and the offline OSV data themselves are not packed into the ZIP.

## 2026-10-11 Fallback Model and Unredacted Test Literal Acceptance

PR #44 added two features: an operator-configured fallback model (`fallback`) and unredacted synthetic test credentials (`unredacted_literals`). Runs #18–#26 then used real models. Models, environment and limits are as in the next section; each run's data is also in real-model-acceptance-2026-10-11.json. These nine runs took about 1.72 million tokens, and the 26 runs about 3.83 million in all.

| Run | Fixture and settings | Result |
|---|---|---|
| #18 | AI agent, vulnerable; Gemini 3.8 Flash reviewer with local Qwen 3.8 27B as its fallback | Gemini refused and the fallback was asked, but Qwen was truncated at 16,000 output tokens; the run stopped at whitebox |
| #19 | As #18, with Qwen's output limit raised to 32,768 | Ran end to end; the native, promptfoo and PyRIT cases all failed (the trusted ledger recorded an unauthorized export). Gemini answered this time, so the fallback was not used; Nemotron was truncated and the run resumed once |
| #20 | Web API, vulnerable; operator cases BOLA and logout; `fixture-web-a` and `fixture-web-b` declared | In the sealed snapshot both session values stayed as written while undeclared passwords stayed redacted, and the first gap recorded "2 of 2". Gemini refused, with no fallback configured; the run stopped at whitebox |
| #21 | As #20, with the local Qwen fallback | Ran end to end; BOLA and logout both failed. No reviewer reported redacted session tokens any more: in #14 they had kept Claude from telling which token logout deletes. The threat model broke a reference rule once and passed on resume |
| #22 | As #21 | Gemini refused and the local Qwen answered in full. The review records `answered_by` and the qwen family, and the whitebox family diversity gate passed. The run then went end to end; BOLA and logout both failed |
| #23 | As #22, with Qwen also the threat modeler's fallback | Gemini refused again and Qwen again answered in full, the family gate passing. The threat modeler did not refuse and met the dataflow rule on its first attempt on the code that states it, so its fallback was not used. The run went end to end with no resume; BOLA and logout both failed |
| #24 | As #23, in an environment rebuilt after a host reboot | Gemini refused and Qwen answered in full, the family gate passing. The threat modeler did not refuse and passed on its first attempt. Nemotron was truncated twice and the SSO session expired once; after three resumes the run went end to end, and BOLA and logout both failed |
| #25 | As #24 | As #24: Gemini refused, Qwen answered, and the threat modeler did not refuse. Nemotron was truncated once; after one resume the run went end to end, and BOLA and logout both failed |
| #26 | As #24 | As #24: Gemini refused, Qwen answered, and the threat modeler did not refuse. The run went end to end with no resume; BOLA and logout both failed |

- **Problems #18 found (fixed in PR #44)**:
  - The fallback was recorded as having answered before it did, so #18's capability limit line is wrong. It now records "asking its fallback" first, and records the answer only once the fallback has given it.
  - When the fallback fails too, the error now names which fallback failed.
- **Fallback answer verified (#22)**: Gemini refused, the local Qwen answered the whole review, the capability limits record the answer, and the family gate checked Qwen. With both local models answering at once on shared hardware, each ran at about 10 tokens per second and whitebox took about 25 minutes.
- **The threat modeler's fallback not yet used**: #23–#26, four runs, all gave the threat modeler a fallback, but it never refused and passed on its first attempt each time, so a fallback writing the threat model after a refusal has not yet been seen with real models. Only unit tests cover that path so far.
- **The environment of #24–#26**: after a host reboot the database, fixture, offline OSV data, runtime profile and console were rebuilt, and the run input was rewritten from the #23 record and the fixture's README. The logout case C-LOGOUT, the two operator requirements, and the commander and threat modeler output limits (16,000) may differ from #23's.
  - After LM Studio restarted, it loaded Nemotron on first request with only an 8,192-token context, so #24's first resume was truncated again; it passed after Nemotron was reloaded with 71,936. Check local models' context before a run.
  - #24's first attempt failed at preflight while LM Studio was not yet reachable; that record went with the old database and is not listed.
- **The threat model's dataflow rule**: #17, #21 and #22 all failed on one rule, a dataflow naming an undeclared asset, because the contract never said that callers and attackers are assets too. The schema descriptions, the threat-modeling instruction and the retry hint now say so, and #22 passed on resume on that code. Once in between the threat modeler (Sonnet) refused; #22 had a fallback only for the Gemini reviewer, so a resume handled it.

## 2026-10-10–11 Real-Model Acceptance

The first runs of the whole workflow with real models. The only targets were the repository's synthetic fixtures, so nothing here says anything about the models' efficacy, detection rate or cost. Each run's settings, stage results and usage are in real-model-acceptance-2026-10-11.json.

- **Models**:
  - Commander (also challenger and architecture mapper): Claude Opus 5.5 (AWS Bedrock, signed with an SSO profile).
  - Reviewers: Gemini 3.8 Flash (Google, OpenAI-compatible endpoint), Claude Sonnet 5.5 (Bedrock) and Nemotron 3 Super (local LM Studio, json_schema mode, 71,936 context). For the AI agent fixture, Gemma 4 31B (Gemini API) replaced Gemini.
  - Threat modeler: finally Claude Sonnet 5.5.
  - Test designer: Gemini 3.8 Flash.
- **Environment**: PostgreSQL 18.6, Docker 29.1.3 and isolated workers. From #11 on, also Semgrep 1.153.0, Gitleaks 8.30.1 and OSV-Scanner 2.3.5 (offline PyPI/npm data), plus the tools image with promptfoo 0.124.1 and PyRIT 1.1.0.
- **Results**: 17 runs, about 2.11 million tokens in all. Five ran end to end, and each gave the expected result:

| Run | Fixture | Cases | Black-box result |
|---|---|---|---|
| #6, #8 | Web API, vulnerable | Model-designed BOLA | fail (tenant B's canary observed) |
| #13 | Web API, fixed | Model-designed BOLA | pass (true negative, no false positive) |
| #14 | Web API, vulnerable, three scanners | Operator cases: BOLA and logout | both fail; the session still worked after logout |
| #17 | AI agent, vulnerable, three scanners | Operator cases: native ×5, promptfoo ×2, PyRIT ×2 | all three fail; the trusted ledger recorded an unauthorized export |

- **The other 12 runs**: each stopped on a problem it exposed, and every one was fixed (PRs #40–#43):
  - LiteLLM put call parameters into the request body.
  - LM Studio accepts only json_schema.
  - Local reasoning models timed out, or probes and outputs were truncated.
  - Gemini returned occasional HTTP 500s and content filtering.
  - A model miscopied a UUID.
  - Threat models broke the reference rules.
  - Threats that model cases cannot cover were marked automated.
  - Gemma refuses maxItems.
  - 4xx rejections were treated as unknown usage.
  - An operator case of my own was wrong: the gate correctly refused it.
- **Not yet solved**: cloud models occasionally refuse to write attack scenarios or to review prompt-injection code: Gemini in #10 and #12, Claude Opus in #5. A refusal leaves a clear record and the run can resume, but the same model usually refuses again. An operator-configured fallback model (the `fallback` role) was added afterwards: it answers when a named Agent refuses or is truncated, and the report records it.

## 2026-10-10 In-Depth Review Fixes

This round fixed the issues a full review found (PR #39, branch fix/deep-review-2026-10-10, with main merged up to c2a027f).

- Re-run this round:
  - Full Linux regression: 1254 passed, 22 skipped, 4 subtests passed (linux-regression-2026-10-10.xml). The environment was Python 3.12.15, PostgreSQL 18.6 (the digest CI pins) and Node 24.21.0.
  - Isolation tests on real Docker: 88 passed, 1 skipped, 4 subtests passed (docker-isolation-2026-10-10.xml). The environment was Docker 29.1.3; the worker image was built on the python digest CI uses.
  - Frontend: type check, vitest, the i18n and message-table checks and the production build all passed.
  - ruff: passed.
  - Dependency audit: the pinned osv-scanner reports no known vulnerabilities in requirements.lock.txt or frontend/package-lock.json.
- Not re-run locally this round:
  - The three offline scanners, the five dynamic tools and the full pipeline: this host had none of those images, so integration.yml runs them in CI instead.
  - The Windows regression and the real Edge browser check.
- Known and not yet handled: the tool image dependencies in deploy/worker/locks carry 14 known vulnerabilities across 11 packages (osv.dev, 2026-10-10). They come from dependencies of promptfoo 0.123.1 and PyRIT, such as simple-git, basic-ftp, sharp and werkzeug, and some have no upstream fix yet. Handling them means updating tool versions, rebuilding the tools image and re-validating it, so this round left them unchanged. That was the 10-10 historical scope gap; the current dependency-drift.py includes both tool-image lockfiles.
- Fixes (see git log for details):
  - Once the supervisor has started, any controller-side failure is reported as outcome_unknown.
  - When the worker returns a malformed result, a leak the supervisor recorded still fails.
  - The supervisor drops supervisor fields that the worker sets itself.
  - A runtime profile cannot select process_test.
  - Broker requests have an overall deadline.
  - The lease deadline covers supervisor startup, container creation and teardown, and the supervisor enforces the worker's own time limit.
  - The sealed body bytes are what gets sent.
  - NAT64 and 6to4 forms of the metadata address are refused.
  - The Docker API version is negotiated.
  - OSV uses only verified ecosystems, and exit code 128 is recorded as a gap.
  - The positive-control contract matches what the executors accept.
  - Model payloads are fitted to the limit.
  - Budget refusals are reported with their reason.
  - Contract checks run inside the bounded retry.
  - Retests take only the relevant cases, and their results are written back to the parent findings.
  - Model-designed cases waiting for approval can be declined.
  - A resume reuses model answers that were already paid for.
  - Console error display, polling backoff and accessibility.

## Acceptance Results

The test groups overlap one another; **do not add the rows together and treat the sum as a count of unique tests**. JUnit's successful records include subtests that are reported separately; the table below uses the test counts as displayed by pytest.

| Acceptance | Actual result | Evidence |
|---|---|---|
| Fallback model and unredacted test literals (2026-10-11) | 9 runs; #19 and #21–#26 end to end, the vulnerable fixtures failing; the declared test sessions stayed unredacted in the snapshot; in #22–#26 the fallback answered a review in full and the family gate passed; the threat modeler did not refuse in four runs, so its fallback not yet used | real-model-acceptance-2026-10-11.json |
| Full workflow with real models (2026-10-10–11) | 17 runs; 5 end to end, the vulnerable fixtures failing (BOLA, logout, AI agent unauthorized export) and the fixed one passing | real-model-acceptance-2026-10-11.json |
| Full Linux regression (2026-10-10, after this round) | 1254 passed, 22 skipped, 4 subtests passed; PostgreSQL 18.6 and Node 24 actually ran | linux-regression-2026-10-10.xml |
| Isolation tests on real Docker (2026-10-10, after this round) | 88 passed, 1 skipped, 4 subtests passed; Docker 29.1.3 | docker-isolation-2026-10-10.xml |
| Full Linux regression (2026-10-05, code at that date) | 363 passed, 21 skipped, 4 subtests passed; the PostgreSQL 18.6 integration (atomic rollback, checkpoint and resume, concurrent lease claim) and the Node 24 Web fixture were actually executed; the skips are 20 integrations requiring Docker images and 1 Windows-only case | linux-regression.xml |
| Full Linux regression with Docker integration (2026-10-05, code at that date) | 383 passed, 1 skipped, 4 subtests passed; the isolated worker, the three offline scanners, the five dynamic tools, the fixture protocol executed with the Docker backend and the full pipeline were all actually executed, and this run also includes the PostgreSQL 18.6 integration and the Node 24 Web fixture; the only skip is Windows-specific. The 10 tests of the blind-review matching tool are also within this receipt's scope | linux-docker-integration.xml |
| Full Linux regression with Docker integration (2026-10-06, code at that date) | 508 passed, 15 skipped, 4 subtests passed; Python 3.12.3, Docker 29.6.2, PostgreSQL 16.14, Node 24.21.0. The isolated worker, white-box containers without a broker, the fixed black-box http_case sequence, the three offline scanners, the fixture protocol on the Docker backend (including supervisor-record verdicts) and the full pipeline were all actually executed. 14 skips are because this host did not build the tools and ZAP images, so the five dynamic tools were not re-verified this time; the 10-05 receipt stands for them. The remaining skip is Windows-specific | linux-docker-integration-2026-10-06.xml |
| Full Linux regression with Docker integration (2026-10-09, code at that date) | 559 passed, 1 skipped, 4 subtests passed; Python 3.13.16, Docker 29.8.2, PostgreSQL 16.15, Node 24.21.0. Re-verified after G4 review rounds 12–24 were merged: the isolated worker, the three offline scanners (with offline OSV data), the five dynamic tools, the fixture protocol on the Docker backend and the full pipeline were all actually executed, together with the PostgreSQL integration and the Node 24 Web fixture; the only skip is Windows-specific. Because the build host reaches the internet through an HTTPS proxy, the tools image was rebuilt from the Dockerfile.tools.locked lockfiles with the proxy CA mounted as a BuildKit secret for the install steps only; its image ID differs from runtime-images.json | linux-docker-integration-2026-10-09.xml |
| Full Windows regression (2026-10-05, code at that date) | 359 passed, 25 skipped, 4 subtests passed | windows-regression.xml |
| PostgreSQL, isolated worker, full workflow | 27 passed, 4 deselected | postgres-pipeline-integration.xml |
| Fixture, reset, stop and failure paths | 24 passed, 3 skipped, 4 subtests passed | runtime-fixture-integration.xml |
| Final workflow and policy checks | 45 passed, 14 skipped | final-guards.xml |
| Dynamic tools and AI lifecycle, fully dependency-locked images | 27 passed; zero failures, zero skips | tool-integration-release.xml |
| Schemathesis header fix | 2 passed, 25 deselected | schemathesis-header-regression.xml |
| Known-issue detection by the three offline scanners | 3 passed | scanner-integration-release.xml |
| Frontend type check and production build (2026-10-05) | Passed, 32 modules; rebuilt with the locked dependencies, the artifacts are byte-identical to frontend/dist | frontend/dist |
| Chromium real browser (2026-10-09, code at that date) | Playwright 1.49.1 driving Chromium 141 headless: three export types, saving a project, traceability, creating a retest, switching the interface between Chinese and English; 0 page errors, no horizontal overflow. Replaces the 2026-10-05 Edge 154 receipt (kept in git history) | browser-validation.json |
| Real FastAPI + React SSR/API | Three synthetic reviews, fail/pass/inconclusive, seven pieces of evidence, five tabs, three export types and HTML escaping; re-run and passed on 2026-10-05 against the current code (including the evidence adjudication console), also confirming that with only a session cookie /api/session and /api/runs are rejected without leaking the CSRF token, and fetch-based SSE and download were verified with Node | api-ssr-validation.json |
| Mutation testing (2026-10-10, code at that date) | mutmut 3.8.0 generated 4,620 mutants of `policy.py`, `adapters.py`, `catalog.py`, `lease.py`, `snapshot.py` and `messages.py` and ran the unit suites against each (lease tests on PostgreSQL included). The third round read every surviving mutant's diff: an observable difference got a precise assertion (whole messages, every limit boundary, optional fields read by their exact names, reads under the PostgreSQL row lock, the full content of observations and evidence), an equivalent mutant a `# pragma: no mutate` with its reason. Result: 4,546 caught, 73 escaped (one timeout not counted). What remains sits in `adapters.py` 36, `policy.py` 14, `snapshot.py` 12, `lease.py` 8 and `catalog.py` 3; `messages.py` 0, nearly all equivalent (a lower-case default before `.upper()`, a missing-key default another check already refuses, a platform constant that is 0 on Linux, a json argument that reads None as False). These are the per-module ceilings in `tests/mutation-baseline.json` (each function's count is recorded too, for a pull request's `--changed` run), down from 1,301 after the first round and 623 after the second; only more tests lower them. A full run always starts from an empty `mutants/` (the script clears it): mutmut reuses the old result of a mutant whose text is unchanged, so new tests would never meet it. | Local `scripts/mutation-test.py` log; `.github/workflows/mutation.yml` was off by default at that date; the 10-31 repair enables automatic runs unless `VIBEAUDIT_MUTATION=false` |
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

- Acceptance of new model versions, endpoints and environments; formal model-quality and cost comparisons; and the user's own staging/backend observations. The 26 recorded real-model runs against synthetic targets do not replace those acceptance checks.
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

## 2026-10-31 review repairs and reproducible validation

This round repairs explicit finding/threat traceability, retest scope, complete counterevidence coverage, unknown model metering, complete case-design scope and bounded batched source review. Dynamic confirmation no longer implies high severity; unspecified impact is unrated. The console shows included text and completed batches per reviewer without claiming full repository coverage.

The tests use a throwaway PostgreSQL instance, existing pinned Docker images and synthetic model contracts. No real keys, new paid-model runs or efficacy experiments were used. Before the fixes, the new regressions recorded 14 failed and 1 passed, demonstrating they catch the original faults. Final passing receipts, environment and source input hashes are recorded in review-validation-2026-10-31.json. Its source_inputs_sha256 excludes documentation and generated artifacts to avoid a self-hashing receipt cycle. These are local receipts, not independent signatures or forensic storage.

Older receipts describe code at their execution date. Historical three-model integration and formal efficacy comparison are separate: 26 real-model runs against synthetic targets are recorded; formal efficacy comparison remains unperformed. Exhaustive semantics for arbitrary frameworks, real-target backend observations and independently adjudicated research data remain external acceptance work, not claims made by this regression run.
