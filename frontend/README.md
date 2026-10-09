# Vibe Audit 本地工作台

React + TypeScript + Vite 前端，Apache-2.0。介面使用繁體中文；所有評估都呼叫實際後端 API。合成示範清楚標示，不冒充真實 LLM 或目標測試。

## 建置與使用

需 Node.js 24，與專案其餘部分一致（TS fixture 以內建 type stripping 執行）；UI 建置本身使用 Vite 8，Node 20.19+ 或 22.12+ 也可建置。

```powershell
cd frontend
npm ci
npm run typecheck
npm test
npm run check:i18n
npm run build
```

`npm test` 以 vitest 在 happy-dom 模擬的瀏覽器裡跑 `tests/` 的單元與元件測試（語言切換、引擎訊息對照、API 用戶端、表單與畫面），不需要後端；`npm run smoke` 才會連真實後端。

建置檔案在 `dist/`。正常使用時由 FastAPI 在同一個本地 origin 提供前端；啟動後端後開啟它印出的 `http://127.0.0.1:8000/#token=…`。

開發模式使用 `npm run dev`，預設 `http://127.0.0.1:5173`，`/api` 代理到 `127.0.0.1:8000`。後端需先設定 `VIBEAUDIT_UI_ORIGINS=http://127.0.0.1:5173`，並開啟 `http://127.0.0.1:5173/#token=…`（使用後端印出的權杖）。代理保留原 Host 與 Origin，不繞過後端的來源檢查。不要公開綁定 `0.0.0.0`。

`npm run preview` 只用於檢查靜態建置，不提供後端 API 代理；完整使用請由 FastAPI 提供 `dist/`。

## 實際連線行為

- 介面有正體中文與英文兩種語言，右上角按鈕切換，選擇記在這個瀏覽器的 localStorage；無法使用儲存空間時維持中文。每段可見文字都在使用處寫成 `t('中文','English')`（見 `src/i18n.ts`）。
- 啟動時從網址 fragment 取出啟動權杖（只存在記憶體並自網址移除），以 `X-VibeAudit-Token` 呼叫 `/api/session` 取得 HttpOnly session cookie 與 CSRF token。cookie 不分 port，所以所有 API 請求（含 GET）都加上 `X-CSRF-Token`；token 存在此分頁的 sessionStorage，重新整理時以它向 `/api/session` 證明 session，新分頁需重新開啟啟動網址。
- 建立評估依序呼叫 `POST /api/runs`、`POST /api/runs/{id}/start`。
- 以 fetch 讀取 SSE（EventSource 無法帶 header）的 `progress` / `done` 更新進度，執行中每 2.5 秒再同步一次狀態。執行結束後停止更新。
- 可啟動、取消及嘗試恢復。是否允許恢復由後端重新驗證閘門決定。
- 匯出 Markdown、JSON、SARIF（以帶 header 的 fetch 下載，失敗時在選單顯示原因）；開啟證據使用受 session 保護的 `/api/runs/{id}/evidence/{artifactId}`。後端負責完整性檢查。

## 資料與安全

- 不使用 CDN、外部字型、分析追蹤或 localStorage；sessionStorage 只保存本機 session 的 CSRF token，不保存金鑰。
- 金鑰欄位只接收 `VIBEAUDIT_*` 環境變數名稱。實際金鑰需在後端環境提供。
- 所有證據、工具結果與目標文字皆用 React 純文字節點呈現；不使用 `dangerouslySetInnerHTML` 或執行 HTML/Markdown。
- 實際評估預設 `local_only`；雲端需明確切換政策與列出模型 origin allowlist。提供每位 Agent 的端點、精確模型 ID、模型家族及輸出預算。
- 三位 reviewer 配置與家族必須不同；模型差異不保證消除共同偏誤。
- live 的精確 `method + path` allowlist 留白代表所有黑箱請求受阻。POST 僅適用可重置的隔離 staging。
- 測試身分可在進階設定新增，僅填環境變數名稱、角色與認證標頭；金鑰不在 UI 輸入。
- UI 驗證是輸入協助；授權、scope、預算、重試、oracle、階段與資料邊界由後端強制執行。

## 功能驗收

1. 先啟動後端，UI 顯示本地服務已連線。
2. 新建「合成示範」，不需路徑、目標或金鑰，按「建立並開始」。
3. 確認顯示合成標籤、三份 synthetic reviewer 結果及真實後端事件。示範含刻意缺證據的情境，最終 `incomplete` 是預期，不應偽裝全部通過。
4. 「威脅與測試」顯示 threat → case → execution 狀態。「發現」的證據 ID 可開啟完整證據並核對摘要。
5. 「執行與證據」保留 `fail`、`pass`、`inconclusive` 差異；報告可匯出且含合成標記。
6. 切到實際評估，不同模型、時間/請求/模型/token 預算、明確 allowlist 可設定；無必要設定時提示輸入問題。
7. 在窄螢幕檢查導覽、表單、階段橫向捲動與證據文字；鍵盤可操作全部控制。

沒有真實 provider credentials 與受授權 staging 時，不聲稱已驗證 live 模型/目標流程。

## 自動契約驗證

後端啟動後，設定 `VIBEAUDIT_SESSION_TOKEN` 為後端的啟動權杖再執行 `npm run smoke`，或 `npm run smoke -- --base-url http://127.0.0.1:8000`。只接受數字 loopback HTTP origin，會留下明確標示的合成評估紀錄。

此檢查實際建立與啟動 demo，驗證三份合成 review、`pass/fail/inconclusive` 結果、所有證據讀取、三種報告，再使用真實 Run 資料渲染 React 的五個報告分頁，並驗證不可信 HTML 以文字跳脫。這是 API 與 React SSR 整合測試；不包含瀏覽器點選、視覺截圖、SSE 重連或真實 LLM／目標驗證。表單互動與窄螢幕仍需依上述功能驗收步驟檢查。

---
# Vibe Audit Local Workbench

React + TypeScript + Vite frontend, Apache-2.0. The interface uses 繁體中文; all evaluations call the real backend API. The synthetic demo is clearly labeled and does not impersonate a real LLM or real target testing.

## Build and Usage

Node.js 24 is required, consistent with the rest of the project (the TS fixture runs with built-in type stripping); the UI build itself uses Vite 8, and Node 20.19+ or 22.12+ can also build it.

```powershell
cd frontend
npm ci
npm run typecheck
npm test
npm run check:i18n
npm run build
```

`npm test` runs the unit and component tests in `tests/` (language switch, engine message table, API client, form and screens) with vitest in a happy-dom simulated browser and needs no backend; `npm run smoke` is the one that talks to a real backend.

The built files are in `dist/`. In normal use, FastAPI serves the frontend on the same local origin; after starting the backend, open the `http://127.0.0.1:8000/#token=…` it prints.

Dev mode uses `npm run dev`, defaulting to `http://127.0.0.1:5173`, with `/api` proxied to `127.0.0.1:8000`. The backend must first have `VIBEAUDIT_UI_ORIGINS=http://127.0.0.1:5173` configured, and you open `http://127.0.0.1:5173/#token=…` (using the token printed by the backend). The proxy preserves the original Host and Origin and does not bypass the backend's origin checks. Do not bind publicly to `0.0.0.0`.

`npm run preview` is only for checking the static build; it does not provide a backend API proxy. For full use, have FastAPI serve `dist/`.

## Actual Connection Behavior

- The interface is in Traditional Chinese (Taiwan) or English. The button at the top right switches it, and the choice is stored in this browser's localStorage; if storage is unavailable the console stays in Chinese. Every visible string is written where it is used as `t('中文','English')` (see `src/i18n.ts`).
- At startup, the launcher token is taken from the URL fragment (kept only in memory and removed from the URL), and `/api/session` is called with `X-VibeAudit-Token` to obtain an HttpOnly session cookie and a CSRF token. Cookies are not port-scoped, so all API requests (including GET) include `X-CSRF-Token`; the token is stored in this tab's sessionStorage, and on refresh it is used to prove the session to `/api/session`; a new tab must reopen the launcher URL.
- Creating an evaluation calls `POST /api/runs` and then `POST /api/runs/{id}/start` in order.
- SSE is read via fetch (EventSource cannot send headers) for `progress` / `done` updates to progress, with an extra status sync every 2.5 seconds while a run is in progress. Updates stop after the run ends.
- Runs can be started, cancelled, and resume attempted. Whether resume is allowed is decided by the backend re-validating the gates.
- Export to Markdown, JSON, and SARIF (downloaded via header-carrying fetch; on failure the menu shows the reason); opening evidence uses the session-protected `/api/runs/{id}/evidence/{artifactId}`. The backend is responsible for integrity checks.

## Data and Security

- No CDN, external fonts, analytics tracking, or localStorage is used; sessionStorage holds only the CSRF token for the local session, not keys.
- Key fields only accept `VIBEAUDIT_*` environment variable names. Actual keys must be provided in the backend environment.
- All evidence, tool results, and target text are rendered with React plain-text nodes; `dangerouslySetInnerHTML` is not used and HTML/Markdown is not executed.
- Real evaluations default to `local_only`; cloud requires explicitly switching the policy and listing the model origin allowlist. Per-agent endpoint, exact model ID, model family, and output budget are provided.
- The three reviewers' configurations and families must differ; model diversity does not guarantee eliminating shared bias.
- An empty exact `method + path` allowlist for live means all black-box requests are blocked. POST applies only to resettable isolated staging.
- Test identities can be added in advanced settings, entering only environment variable names, roles, and auth headers; keys are never entered in the UI.
- UI validation is input assistance; authorization, scope, budgets, retries, oracles, phases, and data boundaries are enforced by the backend.

## Functional Acceptance

1. Start the backend first; the UI shows the local service as connected.
2. Create a new 「合成示範」; no path, target, or keys are needed; press 「建立並開始」.
3. Confirm that the synthetic label, the three synthetic reviewer results, and real backend events are displayed. The demo includes scenarios deliberately missing evidence; the final `incomplete` is expected and must not be disguised as all-pass.
4. 「威脅與測試」 shows threat → case → execution status. Evidence IDs in 「發現」 can open the full evidence and check the summary.
5. 「執行與證據」 preserves the `fail`, `pass`, `inconclusive` distinctions; reports can be exported and include the synthetic marker.
6. Switch to a real evaluation: different models, time/request/model/token budgets, and an explicit allowlist can be configured; when required settings are missing, it prompts for input.
7. On narrow screens, check navigation, forms, horizontal scrolling of phases, and evidence text; all controls are keyboard operable.

Without real provider credentials and authorized staging, no claim is made that live model/target flows have been verified.

## Automated Contract Verification

After the backend starts, set `VIBEAUDIT_SESSION_TOKEN` to the backend's launcher token and then run `npm run smoke`, or `npm run smoke -- --base-url http://127.0.0.1:8000`. Only numeric loopback HTTP origins are accepted, and clearly labeled synthetic evaluation records are left behind.

This check actually creates and starts the demo, verifies the three synthetic reviews, the `pass/fail/inconclusive` results, all evidence reads, and the three report types, then renders React's five report tabs using real Run data, and verifies that untrusted HTML is escaped as text. This is an API and React SSR integration test; it does not include browser clicks, visual screenshots, SSE reconnection, or real LLM/target verification. Form interactions and narrow screens still need to be checked via the functional acceptance steps above.
