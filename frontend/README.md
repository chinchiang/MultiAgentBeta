# Vibe Audit 本地工作台

React + TypeScript + Vite 前端，Apache-2.0。介面使用繁體中文；所有評估都呼叫實際後端 API。合成示範清楚標示，不冒充真實 LLM 或目標測試。

## 建置與使用

需 Node.js 24，與專案其餘部分一致（TS fixture 以內建 type stripping 執行）；UI 建置本身使用 Vite 6，Node 18、20 或 22+ 也可建置。

```powershell
cd frontend
npm ci
npm run typecheck
npm run build
```

建置檔案在 `dist/`。正常使用時由 FastAPI 在同一個本地 origin 提供前端；啟動後端後開啟它印出的 `http://127.0.0.1:8000/#token=…`。

開發模式使用 `npm run dev`，預設 `http://127.0.0.1:5173`，`/api` 代理到 `127.0.0.1:8000`。後端需先設定 `VIBEAUDIT_UI_ORIGINS=http://127.0.0.1:5173`，並開啟 `http://127.0.0.1:5173/#token=…`（使用後端印出的權杖）。代理保留原 Host 與 Origin，不繞過後端的來源檢查。不要公開綁定 `0.0.0.0`。

`npm run preview` 只用於檢查靜態建置，不提供後端 API 代理；完整使用請由 FastAPI 提供 `dist/`。

## 實際連線行為

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

此檢查實際建立與啟動 demo，驗證三份合成 review、`pass/fail/inconclusive` 結果、所有證據讀取、三種報告，再使用真實 Run 資料渲染 React 的五個報告分頁，並驗證不可信 HTML 以文字跳脫。這是 API 與 React SSR 整合測試；不包含瀏覽器點擊、視覺截圖、SSE 重連或真實 LLM／目標驗證。表單互動與窄螢幕仍需依上述功能驗收步驟檢查。
