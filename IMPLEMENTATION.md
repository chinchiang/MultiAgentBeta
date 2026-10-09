# 實作契約 — 0.2.1

權威驗證依據：backend/vibe_audit/domain.py、contracts.py、policy.py 與 docs/run-input.schema.json（schema 版本 2）。

## API

所有路由皆以 /api 開頭；在已有 session 的情況下，未知的 /api 路徑會回傳 JSON 404。GET /session 會以啟動權杖（X-VibeAudit-Token；以 `#token=…` 形式印在啟動 URL 中，或以 VIBEAUDIT_SESSION_TOKEN 固定）換取 8 小時的 HttpOnly SameSite=Strict session cookie 與 CSRF token。其餘所有 /api 請求（含讀取）都必須同時具備該 cookie 與 X-CSRF-Token：cookie 會送達主機上的每個連接埠，因此僅憑 cookie 無法開啟任何東西，而 GET /session 只會把 token 回傳給已出示該 token 的呼叫方。Host/Origin 檢查涵蓋工作區路由。錯誤格式：{detail: ..., detail_zh?: ...}；`detail` 是固定的英文訊息，`detail_zh` 是 `messages.py` 對照表中的正體中文說法（沒有對照時省略）。run 的 `error` 也同樣附帶 `error_zh`，控制台依介面語言顯示。

| Method | Route | Purpose |
|---|---|---|
| GET | /session, /capabilities | Session/CSRF 與實際設定的 runtime 可用性；/capabilities?profile=… 回報該 runtime profile（預設：default） |
| GET | /messages | 引擎固定訊息的正體中文對照表（`messages.py` 的 `exact`、`status` 與 `patterns`）；控制台以它顯示執行紀錄、缺口、判定說明與示範內容，模型、掃描器、目標與操作者的文字維持原文 |
| GET / PUT | /projects, /projects/{id} | 列出／儲存專案設定 |
| GET / PUT | /models, /models/{id} | 列出／儲存 profile；僅限憑證參照 |
| GET | /catalogs?standard=... | 標準 ID、版本與來源出處 |
| POST | /models/probe | 明確的端點契約，含 policy／預算 |
| GET / POST | /runs | 列出 run 摘要（id、名稱、模式、狀態、階段、時間、用量、錯誤；事件、發現與證據紀錄隨 /runs/{id} 回傳）／建立不可變的 manifest |
| GET | /runs/{id} | 狀態、用量、缺口與發現 |
| POST | /runs/{id}/start, /cancel, /resume | 生命週期轉換 |
| GET | /runs/{id}/events | SSE 進度事件 |
| GET | /runs/{id}/trace | 持久化的實體、連結與歷史 |
| GET | /runs/{id}/evidence/{artifact_id} | 綁定於 run、經雜湊驗證的信封 |
| GET | /runs/{id}/report?format=json or markdown or sarif&lang=en or zh-Hant | 經驗證的匯出；lang 只影響 Markdown 報告的用語（預設 en），JSON 與 SARIF 不變 |
| POST | /runs/{id}/retest | 建立連結到原始發現的新 run（trace 記錄 `retests` 連結，Markdown 與 SARIF 會標註父項） |
| POST | /runs/{id}/reconcile | 操作者對 worker 清理的證明；關閉處於 cancelling 狀態的 run，該 run 仍不可恢復（unresumable） |
| POST | /runs/{id}/findings/{finding_id}/decision | 以證據為依據的 refuted／inconclusive 決策：被引用的黑箱執行必須測試該發現的威脅（若該發現沒有威脅連結，由操作者命名這些威脅）；要駁回（refute）需要一次 pass，且該 run 中這些威脅沒有任何失敗；validated_dynamic 狀態的發現只能透過已連結的 retest 清除 |
| GET | /openapi.json | 位於 /api/openapi.json 的 OpenAPI schema（需要 session 與 CSRF token；不提供互動式文件頁面） |

Stages（階段）：新 run 在任何工作開始前會先記錄於 `intake` 階段；實際執行的圖為 preflight → whitebox → adjudication → threat_model → case_design → blackbox → report → complete。
Run 狀態：created/running/cancelling/cancelled/completed/incomplete/blocked/failed。
Finding（發現）狀態：hypothesis/corroborated_static/validated_dynamic/refuted/inconclusive。
Execution（執行）狀態：pass/fail/inconclusive/blocked/execution_error/outcome_unknown。工具執行完成不代表通過安全性檢驗（security pass）。若 fail 的目標重置或其後的 dispatch 未經確認，該發現會保留並標記 target_state_confirmed=false；與 outcome_unknown 一樣，它會停止 run 並阻止 resume。部署識別變更會停止 run（deployment_changed=true）並阻止 resume；每次排定的重複執行只會送出該 case 一次。模型設計的 case 必須符合嚴格的 case contract，而提供的 case 會在 run 建立時做型別檢查。含 supplied 或 retest case 的 run 會把這些 case 未涵蓋的自動化威脅記錄為 gap；威脅模型必須保留每個此類 case 所測試的威脅 ID。Worker 的結果會由 supervisor 的欄位與記錄重建，因此 worker 回傳的多餘鍵無法設定 verdict、observations 或步驟標籤；不論由哪個 executor 執行 case，每個內容 oracle 都需要一個已驗證的 positive control，且該 control 顯示過每個禁止的 canary。在 resume 時，lease journal 顯示已完成的工作會直接回傳其已記錄且已計費的結果，而非重播或要求 reconciliation；prepared 或 sent 狀態的工作永不重播，並保留其 reconciliation 路徑。

## 模組（Modules）

- service：LangGraph 編排、凍結的 manifest、已封存（sealing）的審查、靜態證據聯集、閘門（gate）、含日誌（journal）的執行／報告。
- providers：LiteLLM、明確的 origins／憑證、schema／拒答／截斷驗證、有界的重試、無 fallback、unknown-usage 鎖存。
- staging/snapshot：有界的原始私密掃描器輸入，以及另外去識別化（redacted）的模型情境；儲存庫設定無法控制命令。
- worker_runtime/worker_entry：controller、獨立且受信任的 supervisor、隔離的 worker 與 Unix socket relay。Docker 沒有直接對外連線（egress）；process_test 明確不隔離，且在 production profile 載入時不可用。controller 的結果期限涵蓋 supervisor 有界的容器建立預算加上 teardown，因此緩慢的 daemon 無法為健康的 worker 憑空捏造 unknown 結果。
- lease：持久的 capability 綁定、保留（reservation）帳本、續約／到期、unknown 結果。controller EOF 或到期會在終止前先撤銷 socket。續約在 controller 事件迴圈之外執行；worker guardian 與 controller 心跳可以容忍個別的暫時性 lease 資料庫錯誤（連續三次失敗），但遇到真正的到期或撤銷時會立即 fail closed。
- tool_runners：固定的 input／argv 編譯 → 隔離執行 → 有界的 artifact 收集 → 正規化的 observations → 以 broker 證據為本的 oracle。不允許任意的 shell／腳本。
- fixture_protocol：經審查且具雜湊的 reset/setup/cleanup、session 擷取、由管理員註冊的通用 profile；內建者皆為合成。
- effect_collector：獨立排序的事件與 sink 收執，以僅在 collector 驗證期間存在的 per-call 金鑰進行 HMAC 綁定（儲存的 bundle 是證據記錄，而非可重新驗證的簽章）；目標的 JSON 無法賦予來源證明（provenance）。
- store/traceability：正式環境用 PostgreSQL、示範用 SQLite、atomic 的 job/run 提交、版本化的實體／證據連結；事件存在自己的 append 表（每次存檔只寫入尚未儲存的事件，run 本體不含事件），進度串流只讀游標之後的事件，`/runs` 清單只讀摘要。
- catalog：釘選的標準 ID、版本／來源檢查；類別歸屬不等於測試涵蓋或認證。
- settings：後端程序的 VIBEAUDIT_* 設定在同一處讀取並檢查（啟動權杖的格式與強度、資料目錄、資料庫 URL、控制台 origins 正規化為瀏覽器送出的形式、來源根目錄、目錄與設定檔路徑）；憑證 reference 不是設定，仍由 adapters／providers／supervisor 依 run 或 profile 給的名稱各自讀取。
- benchmark：七個比較臂（arm）、共用的預算／工具證據、獨立的 ground truth 與不完整項目的計量。合成 run 僅驗證管線本身。

## 角色與證據

Live 模式需要一名 commander 與三個不同的 reviewer 設定／家族。選用的專職 architecture_mapper、challenger、threat_modeler 與 test_designer 可以使用經核准的獨立端點；否則由 commander 扮演這些角色。報告只驗證既有證據；選用的專職 reporter 只能重新排列確切既有的 finding ID 順序，不能建立新的主張。模型不能新增目標、執行 shell、變更網路政策，也不能以多數決確認發現。

Reviewers 收到相同的核心問題與快照，但不包含掃描器的發現或其他 reviewer 的結論。靜態掃描器可並行執行，但只有在初始批次封存後才會加入。缺少 reviewer 就無法產出完整的三模型審查。

Case 會綁定威脅模型、需求、原始碼、fixture 與 case 的雜湊。Control 與 cleanup 也必須在範圍內。部署變更需要新的 run；unknown 結果需要 reconciliation/reset。

請參閱 docs/LINUX_SETUP.md、docs/VALIDATION.md 與 docs/DELIVERY.md。

---
# Implementation contract — 0.2.1

Authoritative validation: backend/vibe_audit/domain.py, contracts.py, policy.py and docs/run-input.schema.json (schema version 2).

## API

All routes start with /api; with a session, an unknown /api path is a JSON 404. GET /session exchanges the startup token (X-VibeAudit-Token; printed as `#token=…` in the launch URL, or fixed with VIBEAUDIT_SESSION_TOKEN) for an 8-hour HttpOnly SameSite=Strict session cookie and the CSRF token. Every other /api request, reads included, needs both the cookie and X-CSRF-Token: cookies reach every port on the host, so the cookie alone opens nothing, and GET /session returns the token only to a caller that already presents it. Host/Origin checks include workspace routes. Errors: {detail: ..., detail_zh?: ...}; `detail` is the stable English message and `detail_zh` its Traditional Chinese wording from the table in `messages.py` (omitted when there is none). A run's `error` likewise carries `error_zh`; the console shows the one for its language.

| Method | Route | Purpose |
|---|---|---|
| GET | /session, /capabilities | Session/CSRF and actual configured runtime availability; /capabilities?profile=… reports that runtime profile (default: default) |
| GET | /messages | Traditional Chinese table for the engine's fixed messages (`exact`, `status` and `patterns` from `messages.py`); the console uses it for the activity log, gaps, verdicts and demo content, and leaves model, scanner, target and operator text as written |
| GET / PUT | /projects, /projects/{id} | List/save project settings |
| GET / PUT | /models, /models/{id} | List/save profiles; credential references only |
| GET | /catalogs?standard=... | Canonical IDs, versions and provenance |
| POST | /models/probe | Explicit endpoint contract with policy/budget |
| GET / POST | /runs | List run summaries (id, name, mode, status, stage, times, usage, error; events, findings and evidence records come with /runs/{id}) / create immutable manifests |
| GET | /runs/{id} | State, usage, gaps and findings |
| POST | /runs/{id}/start, /cancel, /resume | Lifecycle transitions |
| GET | /runs/{id}/events | SSE progress events |
| GET | /runs/{id}/trace | Persisted entities, links and history |
| GET | /runs/{id}/evidence/{artifact_id} | Run-bound, hash-verified envelope |
| GET | /runs/{id}/report?format=json or markdown or sarif&lang=en or zh-Hant | Verified export; lang changes only the Markdown report's wording (default en), JSON and SARIF stay the same |
| POST | /runs/{id}/retest | New run linked to original findings (trace `retests` links, Markdown and SARIF note the parent) |
| POST | /runs/{id}/reconcile | Operator attestation of worker cleanup; closes a cancelling run, which stays unresumable |
| POST | /runs/{id}/findings/{finding_id}/decision | Evidence-backed refuted/inconclusive decision: cited black-box executions must test the finding's threats (the operator names them for a finding without threat links); refuting needs a pass and no failure of those threats in the run; a validated_dynamic finding is cleared only by a linked retest |
| GET | /openapi.json | OpenAPI schema at /api/openapi.json (session and CSRF token required; no interactive docs page) |

Stages: a new run is recorded at stage `intake` before any work; the executed graph is preflight → whitebox → adjudication → threat_model → case_design → blackbox → report → complete.
Run status: created/running/cancelling/cancelled/completed/incomplete/blocked/failed.
Finding state: hypothesis/corroborated_static/validated_dynamic/refuted/inconclusive.
Execution state: pass/fail/inconclusive/blocked/execution_error/outcome_unknown. Tool completion does not imply security pass. A fail whose target reset, or a later dispatch, is unconfirmed keeps its finding and carries target_state_confirmed=false; like outcome_unknown it stops the run and blocks resume. A deployment-identity change stops the run (deployment_changed=true) and blocks resume; each scheduled repetition sends the case once. Model-designed cases must match a strict case contract, and supplied cases are type-checked when the run is created. Runs with supplied or retest cases record automated threats those cases leave out as gaps; the threat model must keep every threat ID such a case tests. Worker results are rebuilt from supervisor fields and records, so extra keys a worker returns cannot set a verdict, observations or step labels; every content oracle needs a verified positive control that showed each forbidden canary, whatever executor ran the case. On resume, a task the lease journal shows finished returns its recorded, paid result instead of replaying or demanding reconciliation; prepared or sent tasks are never replayed and keep their reconciliation path.

## Modules

- service: LangGraph orchestration, frozen manifests, sealed reviews, static evidence union, gates, journaled execution/report.
- providers: LiteLLM, explicit origins/credentials, schema/refusal/truncation validation, bounded retries, no fallback, unknown-usage latch.
- staging/snapshot: bounded raw private scanner input and separately redacted model context; repository config cannot control commands.
- worker_runtime/worker_entry: controller, independent trusted supervisor, isolated worker and Unix socket relay. Docker has no direct egress; process_test is explicitly unisolated and unavailable in production profile loading. The controller's result deadline covers the supervisor's bounded container-create budget plus teardown, so a slow daemon cannot invent an unknown outcome for a healthy worker.
- lease: persistent capability binding, reservation ledger, renewal/expiry, unknown outcomes. Controller EOF or expiry revokes sockets before termination. Renewals run off the controller event loop; the worker guardian and controller heartbeat tolerate isolated transient lease-database errors (three consecutive failures) but fail closed immediately on real expiry or revocation.
- tool_runners: fixed input/argv compilation → isolated execution → bounded artifact collection → normalized observations → oracle over broker evidence. No arbitrary shell/scripts.
- fixture_protocol: hashed reviewed reset/setup/cleanup, session capture, administrator-registered generic profiles; built-ins are synthetic.
- effect_collector: independent sequenced events and sink receipts, HMAC-bound under a per-call key that exists only while the collector verifies them (stored bundles are evidence records, not re-verifiable signatures); target JSON cannot confer provenance.
- store/traceability: PostgreSQL production, SQLite demo, atomic job/run commits, versioned entities/evidence links; events live in their own append-only table (a save writes only the events not yet stored and the run body carries none), the progress stream reads only the events after its cursor, and the `/runs` inventory reads summaries alone.
- catalog: pinned canonical IDs, version/source checks; category membership is not test coverage or certification.
- settings: the backend process's VIBEAUDIT_* settings, read and checked in one place (startup token format and strength, data directory, database URL, console origins normalised to the form a browser sends, source roots, catalog and configuration paths); credential references are not settings and stay with adapters/providers/the supervisor, read by the names a run or profile gives.
- benchmark: seven comparative arms, common budgets/tool evidence, independent ground truth and incomplete accounting. Synthetic runs verify plumbing only.

## Roles and evidence

Live requires one commander and three distinct reviewer configurations/families. Optional dedicated architecture_mapper, challenger, threat_modeler and test_designer can use approved separate endpoints; otherwise the commander performs those roles. Reports verify existing evidence; an optional dedicated reporter may only reorder the exact existing finding IDs and cannot create claims. Models cannot add targets, run shell, change network policy or confirm findings by majority vote.

Reviewers receive the same core questions and snapshot without scanner findings or other reviewers' conclusions. Static scanners run concurrently but join only after the initial batch is sealed. Missing reviewers cannot produce a completed three-model review.

Cases bind threat model, requirement, source, fixture and case hashes. Controls and cleanup must also be in scope. Deployment change requires a new run; unknown outcomes require reconciliation/reset.

See docs/LINUX_SETUP.md, docs/VALIDATION.md and docs/DELIVERY.md.
