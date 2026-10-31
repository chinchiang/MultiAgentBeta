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
| POST | /runs/{id}/start, /cancel, /resume | 生命週期轉換；對 awaiting_approval 的 run 呼叫 /cancel 即退回模型設計的案例（狀態改為 cancelled，不送出任何請求；之後 resume 會重新交付審視） |
| POST | /runs/{id}/approve-cases | 操作者核准確切的封存案例集（{receipt}：run 的 gate_receipts.cases），記錄為 operator-attestation 證據後恢復進入黑箱執行 |
| GET | /runs/{id}/events | SSE 進度事件 |
| GET | /runs/{id}/trace | 持久化的實體、連結與歷史 |
| GET | /runs/{id}/evidence/{artifact_id} | 綁定於 run、經雜湊驗證的信封 |
| GET | /runs/{id}/report?format=json or markdown or sarif&lang=en or zh-Hant | 經驗證的匯出；lang 只影響 Markdown 報告的用語（預設 en），JSON 與 SARIF 不變 |
| POST | /runs/{id}/retest | 建立連結到原始發現的新 run（trace 記錄 `retests` 連結，Markdown 與 SARIF 會標註父項）。只複製測試所選發現之威脅的上層案例；任一所選發現缺乏威脅追溯時拒絕建立複測，須先在新評估中建立對應。複測完成後，每個上層發現都會新增一筆 `retests`（pass/fail/inconclusive/untraced）；validated_dynamic 的發現只有在測試其威脅的每個案例都執行且 pass 時，才會變成 resolved_in_retest；之後的複測再次觀測到違規時，會回到 validated_dynamic |
| POST | /runs/{id}/reconcile | 操作者對 worker 清理的證明；關閉處於 cancelling 狀態的 run，該 run 仍不可恢復（unresumable） |
| POST | /runs/{id}/findings/{finding_id}/decision | 以證據為依據的 refuted／inconclusive 決策：被引用的黑箱執行必須測試該發現的威脅（若該發現沒有威脅連結，由操作者命名這些威脅）；要駁回（refute）必須引用所有相關案例、每次重複與每個威脅的通過證據；缺少、未引用、證據不足或失敗的執行均不能排除整筆發現；validated_dynamic 狀態的發現只能透過已連結的 retest 清除 |
| GET | /openapi.json | 位於 /api/openapi.json 的 OpenAPI schema（需要 session 與 CSRF token；不提供互動式文件頁面） |

Stages（階段）：新 run 在任何工作開始前會先記錄於 `intake` 階段；實際執行的圖為 preflight → whitebox → adjudication → threat_model → case_design → blackbox → report → complete。
Run 狀態：created/awaiting_approval/running/cancelling/cancelled/completed/incomplete/blocked/failed。案例由模型設計的 live run 會在送出任何黑箱請求前停在 awaiting_approval。
Finding（發現）狀態：hypothesis/corroborated_static/validated_dynamic/resolved_in_retest/refuted/inconclusive。
Execution（執行）狀態：pass/fail/inconclusive/blocked/execution_error/outcome_unknown。工具執行完成不代表通過安全性檢驗（security pass）。若 fail 的目標重置或其後的 dispatch 未經確認，該發現會保留並標記 target_state_confirmed=false；與 outcome_unknown 一樣，它會停止 run 並阻止 resume。部署識別變更會停止 run（deployment_changed=true）並阻止 resume；每次排定的重複執行只會送出該 case 一次。模型設計的 case 必須符合嚴格的 case contract，而提供的 case 會在 run 建立時做型別檢查。含 supplied 或 retest case 的 run 會把這些 case 未涵蓋的自動化威脅記錄為 gap；威脅模型必須保留每個此類 case 所測試的威脅 ID。Worker 的結果會由 supervisor 的欄位與記錄重建，因此 worker 回傳的多餘鍵無法設定 verdict、observations 或步驟標籤；不論由哪個 executor 執行 case，每個內容 oracle 都需要一個已驗證的 positive control，且該 control 顯示過每個禁止的 canary。在 resume 時，lease journal 顯示已完成的工作會直接回傳其已記錄且已計費的結果，而非重播或要求 reconciliation；prepared 或 sent 狀態的工作永不重播，並保留其 reconciliation 路徑。

## 模組（Modules）

- service：LangGraph 編排、凍結的 manifest、已封存（sealing）的審查、靜態證據聯集、閘門（gate）、含日誌（journal）的執行／報告。每個模型 payload 都依 512 KiB 上限裁切：超過時，先省略沒有發現引用的最大檔案文字，並記為缺口。恢復的階段若會問同一個問題，就重用已付費的 challenger、mapper、threat modeler 或 test designer 答案；未通過階段檢查的答案不保留。預算或時間拒絕以原本的原因呈現（blocked），不會變成一般的 provider 失敗。
- providers：LiteLLM、明確的 origins／憑證（Bedrock 以 VIBEAUDIT_BEDROCK_PROFILES 列出的 AWS profile 簽章，端點限 bedrock-runtime.<region>.amazonaws.com；公司內網閘道須列在 VIBEAUDIT_PRIVATE_MODEL_ORIGINS 才可解析到 RFC 1918／ULA，可用 VIBEAUDIT_PRIVATE_MODEL_CA_FILE 指定只用於這些 origin 的 CA）、schema／拒答／截斷驗證、JSON schema 無法表達的合約檢查（同樣在有界重試內）、providers 本身無 fallback、unknown-usage 鎖存（HTTP 狀態不作為未計費證明；已送出的失敗若沒有可驗證用量（含 HTTP 4xx、429、5xx 與逾時），保留預留額並阻擋後續模型呼叫及付費恢復；確認未送出的失敗按零用量處理）。json_schema 模式送給端點的 schema 不含 maxItems（Gemini API 會以 400 拒絕），回覆仍在本機依完整 schema 驗證。
- staging/snapshot：有界的原始私密掃描器輸入，以及另外去識別化（redacted）的模型情境；儲存庫設定無法控制命令。`unredacted_literals` 列出的確切值（6 到 200 個字元，最多 50 個）是操作者宣告的合成測試憑證：整個值完全相同才不遮蔽，只包含它的值仍會遮蔽；快照的第一項缺口記下有幾個出現在快照裡；與模型金鑰（run 的或環境綁定到模型 origin 的）相同時預檢拒絕。
- worker_runtime/worker_entry：controller、獨立且受信任的 supervisor、隔離的 worker 與 Unix socket relay。Docker 沒有直接對外連線（egress）；process_test 明確不隔離，runtime profile 只能選用 Docker 後端。supervisor 從 worker 啟動起以 timeout_seconds 限制 worker；lease 與 controller 的結果期限另涵蓋 supervisor 啟動、有界的容器建立預算與 teardown。supervisor 啟動之後，controller 端的任何失敗都是 outcome_unknown，不會回報「未送出」；worker 回傳格式錯誤時為 execution_error，並保留 supervisor 的紀錄，已記錄的外洩仍判 fail。只有 supervisor 或 controller 能設定的欄位會從 worker 的 JSON 中丟棄。一次轉送請求（從 broker lock 到最後一個位元組）在 9 秒內結束，早於 relay 與工具 client 的 10 秒逾時；目標收到的是封存的 body 位元組。Docker Engine API 版本與 daemon 協商（1.44–1.52）。controller 的結果期限涵蓋 supervisor 有界的容器建立預算加上 teardown，因此緩慢的 daemon 無法為健康的 worker 憑空捏造 unknown 結果。
- lease：持久的 capability 綁定、保留（reservation）帳本、續約／到期、unknown 結果。controller EOF 或到期會在終止前先撤銷 socket。續約在 controller 事件迴圈之外執行；worker guardian 與 controller 心跳可以容忍個別的暫時性 lease 資料庫錯誤（每個 TTL 續約四次；連續兩次失敗仍可容忍，第三次即結束 worker），但遇到真正的到期或撤銷時會立即 fail closed。
- tool_runners：固定的 input／argv 編譯 → 隔離執行 → 有界的 artifact 收集 → 正規化的 observations → 以 broker 證據為本的 oracle。不允許任意的 shell／腳本。
- fixture_protocol：經審查且具雜湊的 reset/setup/cleanup、session 擷取、由管理員註冊的通用 profile；內建者皆為合成。
- effect_collector：獨立排序的事件與 sink 收執，以僅在 collector 驗證期間存在的 per-call 金鑰進行 HMAC 綁定（儲存的 bundle 是證據記錄，而非可重新驗證的簽章）；目標的 JSON 無法賦予來源證明（provenance）。
- store/traceability：正式環境用 PostgreSQL、示範用 SQLite、atomic 的 job/run 提交、版本化的實體／證據連結；事件存在自己的 append 表（每次存檔只寫入尚未儲存的事件，run 本體不含事件），進度串流只讀游標之後的事件，`/runs` 清單只讀摘要。
- catalog：釘選的標準 ID、版本／來源檢查；類別歸屬不等於測試涵蓋或認證。
- settings：後端程序的 VIBEAUDIT_* 設定在同一處讀取並檢查（啟動權杖的格式與強度、資料目錄、資料庫 URL、控制台 origins 正規化為瀏覽器送出的形式、來源根目錄、目錄與設定檔路徑）；憑證 reference 不是設定，仍由 adapters／providers／supervisor 依 run 或 profile 給的名稱各自讀取。
- benchmark：七個比較臂（arm）、共用的預算／工具證據、獨立的 ground truth 與不完整項目的計量。合成 run 僅驗證管線本身。

## 角色與證據

Live 模式需要一名 commander 與三個不同的 reviewer 設定／家族。選用的專職 architecture_mapper、challenger、threat_modeler 與 test_designer 可以使用經核准的獨立端點；否則由 commander 扮演這些角色。選用的 fallback Agent 以 `fallback_for` 列出它代替的 Agent：只在那些 Agent 拒答（refusal）或輸出被截斷（truncated）時代答，其他失敗照常停止 run；它和其他模型一樣在預檢探測、計入同一份預算，每次代答都記在活動紀錄與報告的能力限制，審查結果記下實際撰寫的模型（`answered_by`），所以家族多樣性閘門檢查的是它；審查員的備援因此必須是其他審查員沒用的家族，每個 Agent 最多一個備援。報告只驗證既有證據；選用的專職 reporter 只能重新排列確切既有的 finding ID 順序，不能建立新的主張。模型不能新增目標、執行 shell、變更網路政策，也不能以多數決確認發現。

Reviewers 收到相同的核心問題與快照，但不包含掃描器的發現或其他 reviewer 的結論。靜態掃描器可並行執行，但只有在初始批次封存後才會加入。缺少 reviewer 就無法產出完整的三模型審查。

Case 會綁定威脅模型、需求、原始碼、fixture 與 case 的雜湊。Control 與 cleanup 也必須在範圍內。部署變更需要新的 run；unknown 結果需要 reconciliation/reset。

請參閱 docs/LINUX_SETUP.md、docs/VALIDATION.md 與 docs/DELIVERY.md。

## 2026-10-31 審查修正的契約

白箱模型與掃描器的發現透過 threats[].finding_ids 明確連結威脅；finding_gaps 保存無法對應的原因，缺少對應不得悄悄複測。歷史發現沒有威脅連結時，建立複測會被拒絕。排除發現需要引用所有相關案例、每次重複與每個威脅的通過證據；缺少、未引用、證據不足或失敗的執行均不能排除整筆發現。複測同樣不能略過原先相關案例。動態違規的證據狀態與嚴重度分開：採用操作者在案例指定的 severity，未指定則為 unrated（尚未評級），不再一律列為高風險。

模型端點的 HTTP 狀態不作為未計費證明；已送出的失敗若沒有可驗證用量，保留預留額並阻擋付費恢復。案例設計輸入含完整 allowed_requests、model_body、model_headers 與 fixture_profile，不含憑證值，也不含不可供模型選用的身分。

原始碼 intake 上限為 2,000 檔、每檔 256 KiB、總量 8 MiB，仍受 5,000 項目與深度上限限制。三位 reviewer 以有界批次閱讀所有已納入的文字，保留原始路徑與 line_start；每批答案依輸入雜湊快取。review_coverage 記錄納入檔數、字元數與每位 reviewer 完成的批次。超過 intake 上限、無法解析與跨檔案語意未知仍列為缺口；後續架構與威脅建模的情境裁切也保留缺口，不宣稱完整語意分析。

## 模型呼叫 module

`model_calls.py` 的 `ModelCalls.answer` 回傳 `ModelAnswer(data, answered_by)`；階段 caller 不再傳入可變的回答者清單。module 管理每次嘗試的預留、結算、明確備援、答案快取與保存；`probe` 使用相同計量 implementation。providers 的 request hook 在每次有界格式重試前預留預算。未知用量保留額度，取消只結算自身預留；快取的 binding、data 與 answered_by 欄位維持既有格式。底層傳輸與格式驗證重試仍位於 providers adapter。

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
| POST | /runs/{id}/start, /cancel, /resume | Lifecycle transitions; /cancel on an awaiting_approval run declines its model-designed cases (status cancelled, nothing sent; a resume brings them back for review) |
| POST | /runs/{id}/approve-cases | Operator approval of the exact sealed case set ({receipt}: the run's gate_receipts.cases), recorded as an operator-attestation artifact; then resumes into black-box execution |
| GET | /runs/{id}/events | SSE progress events |
| GET | /runs/{id}/trace | Persisted entities, links and history |
| GET | /runs/{id}/evidence/{artifact_id} | Run-bound, hash-verified envelope |
| GET | /runs/{id}/report?format=json or markdown or sarif&lang=en or zh-Hant | Verified export; lang changes only the Markdown report's wording (default en), JSON and SARIF stay the same |
| POST | /runs/{id}/retest | New run linked to original findings (trace `retests` links, Markdown and SARIF note the parent). Only the parent cases testing the selected findings' threats are copied; creating a retest is refused if any selected finding lacks threat traceability, which must first be established in a new assessment. When the retest finishes, each parent finding gets a `retests` entry (pass/fail/inconclusive/untraced); a validated_dynamic finding becomes resolved_in_retest only when every case testing its threats ran and passed, and returns to validated_dynamic when a later retest observes the violation again |
| POST | /runs/{id}/reconcile | Operator attestation of worker cleanup; closes a cancelling run, which stays unresumable |
| POST | /runs/{id}/findings/{finding_id}/decision | Evidence-backed refuted/inconclusive decision: cited black-box executions must test the finding's threats (the operator names them for a finding without threat links); refuting requires cited passing evidence for every related case, repetition and threat; missing, uncited, insufficient or failed executions cannot refute the whole finding; a validated_dynamic finding is cleared only by a linked retest |
| GET | /openapi.json | OpenAPI schema at /api/openapi.json (session and CSRF token required; no interactive docs page) |

Stages: a new run is recorded at stage `intake` before any work; the executed graph is preflight → whitebox → adjudication → threat_model → case_design → blackbox → report → complete.
Run status: created/awaiting_approval/running/cancelling/cancelled/completed/incomplete/blocked/failed. A live run whose cases were designed by a model stops at awaiting_approval before any black-box request.
Finding state: hypothesis/corroborated_static/validated_dynamic/resolved_in_retest/refuted/inconclusive.
Execution state: pass/fail/inconclusive/blocked/execution_error/outcome_unknown. Tool completion does not imply security pass. A fail whose target reset, or a later dispatch, is unconfirmed keeps its finding and carries target_state_confirmed=false; like outcome_unknown it stops the run and blocks resume. A deployment-identity change stops the run (deployment_changed=true) and blocks resume; each scheduled repetition sends the case once. Model-designed cases must match a strict case contract, and supplied cases are type-checked when the run is created. Runs with supplied or retest cases record automated threats those cases leave out as gaps; the threat model must keep every threat ID such a case tests. Worker results are rebuilt from supervisor fields and records, so extra keys a worker returns cannot set a verdict, observations or step labels; every content oracle needs a verified positive control that showed each forbidden canary, whatever executor ran the case. On resume, a task the lease journal shows finished returns its recorded, paid result instead of replaying or demanding reconciliation; prepared or sent tasks are never replayed and keep their reconciliation path.

## Modules

- service: LangGraph orchestration, frozen manifests, sealed reviews, static evidence union, gates, journaled execution/report. Every model payload is fitted to the 512 KiB limit: past it, the largest files no finding cites lose their text first and the omission is a gap. A resumed stage reuses a paid challenger, mapper, threat-modeler or test-designer answer when it would ask the same question; an answer that failed its stage checks is not kept. A budget or time refusal reaches the run as itself (blocked), not as a generic provider failure.
- providers: LiteLLM, explicit origins/credentials (Bedrock signs with an AWS profile listed in VIBEAUDIT_BEDROCK_PROFILES, and its endpoint must be bedrock-runtime.<region>.amazonaws.com; a company-network gateway may resolve to RFC 1918/ULA only when listed in VIBEAUDIT_PRIVATE_MODEL_ORIGINS, and VIBEAUDIT_PRIVATE_MODEL_CA_FILE names a CA used for those origins only), schema/refusal/truncation validation, contract checks a JSON schema cannot state (inside the same bounded retry), no fallback in providers itself, unknown-usage latch (an HTTP status is not proof of unbilled usage; sent failures without verifiable metering, including HTTP 4xx, 429, 5xx and timeouts, retain their reservations and block further model calls and paid resume; failures confirmed unsent are treated as zero usage). In json_schema mode the schema sent to the endpoint has no maxItems, which Gemini's API refuses with HTTP 400; answers are still validated locally against the full schema.
- staging/snapshot: bounded raw private scanner input and separately redacted model context; repository config cannot control commands. The exact values in `unredacted_literals` (6 to 200 characters, at most 50) are synthetic test credentials the operator declares: only a whole value identical to one stays unredacted, and a value that merely contains one is still redacted; the snapshot's first gap records how many appear in it; preflight refuses one equal to a model key (the run's, or one the environment binds to a model origin).
- worker_runtime/worker_entry: controller, independent trusted supervisor, isolated worker and Unix socket relay. Docker has no direct egress; process_test is explicitly unisolated, and a runtime profile can only select the Docker backend. The supervisor limits the worker to timeout_seconds from its start; the lease and the controller's result deadline also cover supervisor startup, the bounded container-create budget and teardown. Once the supervisor has started, any controller-side failure is outcome_unknown, never "nothing sent"; a malformed worker result is execution_error and keeps the supervisor's records, so a recorded leak still fails. Fields only the supervisor or controller set are dropped from the worker's JSON. One relayed request, broker lock to last byte, ends within 9 seconds, before the 10-second relay and tool clients give up, and the target receives the sealed body bytes. The Docker Engine API version is negotiated (1.44–1.52). The controller's result deadline covers the supervisor's bounded container-create budget plus teardown, so a slow daemon cannot invent an unknown outcome for a healthy worker.
- lease: persistent capability binding, reservation ledger, renewal/expiry, unknown outcomes. Controller EOF or expiry revokes sockets before termination. Renewals run off the controller event loop; the worker guardian and controller heartbeat tolerate isolated transient lease-database errors (four renewals per TTL: two consecutive failures are tolerated and the third ends the worker) but fail closed immediately on real expiry or revocation.
- tool_runners: fixed input/argv compilation → isolated execution → bounded artifact collection → normalized observations → oracle over broker evidence. No arbitrary shell/scripts.
- fixture_protocol: hashed reviewed reset/setup/cleanup, session capture, administrator-registered generic profiles; built-ins are synthetic.
- effect_collector: independent sequenced events and sink receipts, HMAC-bound under a per-call key that exists only while the collector verifies them (stored bundles are evidence records, not re-verifiable signatures); target JSON cannot confer provenance.
- store/traceability: PostgreSQL production, SQLite demo, atomic job/run commits, versioned entities/evidence links; events live in their own append-only table (a save writes only the events not yet stored and the run body carries none), the progress stream reads only the events after its cursor, and the `/runs` inventory reads summaries alone.
- catalog: pinned canonical IDs, version/source checks; category membership is not test coverage or certification.
- settings: the backend process's VIBEAUDIT_* settings, read and checked in one place (startup token format and strength, data directory, database URL, console origins normalised to the form a browser sends, source roots, catalog and configuration paths); credential references are not settings and stay with adapters/providers/the supervisor, read by the names a run or profile gives.
- benchmark: seven comparative arms, common budgets/tool evidence, independent ground truth and incomplete accounting. Synthetic runs verify plumbing only.

## Roles and evidence

Live requires one commander and three distinct reviewer configurations/families. Optional dedicated architecture_mapper, challenger, threat_modeler and test_designer can use approved separate endpoints; otherwise the commander performs those roles. An optional fallback Agent lists the Agents it stands in for in `fallback_for`: it answers only when one of them refuses (refusal) or is truncated (truncated), and any other failure still stops the run. It is probed at preflight and charged to the same budget as any model; each answer it gives is recorded in the activity log and the report's capability limits, and a review records the model that actually wrote it (`answered_by`), so the family diversity gate checks that one. A reviewer's fallback must therefore be a family no other reviewer uses, and each Agent has at most one fallback. Reports verify existing evidence; an optional dedicated reporter may only reorder the exact existing finding IDs and cannot create claims. Models cannot add targets, run shell, change network policy or confirm findings by majority vote.

Reviewers receive the same core questions and snapshot without scanner findings or other reviewers' conclusions. Static scanners run concurrently but join only after the initial batch is sealed. Missing reviewers cannot produce a completed three-model review.

Cases bind threat model, requirement, source, fixture and case hashes. Controls and cleanup must also be in scope. Deployment change requires a new run; unknown outcomes require reconciliation/reset.

See docs/LINUX_SETUP.md, docs/VALIDATION.md and docs/DELIVERY.md.

## Contracts of the 2026-10-31 review repairs

White-box model and scanner findings explicitly link to threats through threats[].finding_ids. finding_gaps records unmapped reasons; a missing mapping cannot silently create a retest. Retests of historical findings without threat links are refused. Refuting a finding requires cited passing evidence for every related case, repetition and threat; missing, uncited, inconclusive or failed executions cannot refute the whole finding. Retests likewise cannot omit originally related cases. Dynamic confirmation and impact severity are separate: the operator may specify case severity; otherwise the finding is unrated instead of automatically high.

An HTTP status is not proof of unbilled usage. Sent failures without verifiable metering retain their reservations and block paid resume. Case-design input includes the complete allowed_requests, model_body, model_headers and fixture_profile; it contains no credential values or identities that the operator did not make model-selectable.

Source intake is bounded at 2,000 files, 256 KiB per file and 8 MiB total, still subject to 5,000 entries and the depth limit. All three reviewers read every included character in bounded batches with original paths and line_start; each batch answer is cached against its input hash. review_coverage records included file/character counts and each reviewer's completed batches. Intake omissions, parsing failures and unknown cross-file semantics remain gaps; later architecture/threat context trimming also records gaps and makes no exhaustive semantic-analysis claim.

## Model-call module

`ModelCalls.answer` in `model_calls.py` returns `ModelAnswer(data, answered_by)`; stage callers no longer pass a mutable author list. The module owns per-attempt reservations, settlement, explicit fallback, answer caching and persistence; `probe` shares the accounting implementation. The providers request hook reserves budget before each bounded format retry. Unknown usage retains its reservation, and cancellation settles only its own reservations. Cache binding, data and answered_by fields retain their existing format. Transport and format-validation retries remain in the providers adapter.
