# 本地合成 AI Agent 應用靶場

這是 **deterministic mock，不會呼叫任何 LLM**。它只用固定 marker 模擬「從不可信文件提出工具請求」，方便測試 retrieval 與工具政策、事件記錄、oracle。它不能證明 Claude、Nemotron、ChatGPT 等模型受到提示注入的機率，也不能替真實後端背書。

只有 Python 標準函式庫，固定監聽 `127.0.0.1`，無外部網路、磁碟 sink 或 shell 執行。

```powershell
python fixtures/ai-agent/server.py --mode fixed --port 8912
python fixtures/ai-agent/server.py --mode vulnerable --port 8912
```

兩個命令擇一；`--port 0` 配置可用埠並在首行 JSON 回報。停止按 Ctrl+C。公開的合成 bearer tokens：A=`fixture-ai-a`、B=`fixture-ai-b`。

| 介面 | 用途 |
|---|---|
| `GET /documents/doc-a`、`/documents/doc-b` | 方便工具包 GET positive control；回傳 `documents` 陣列 |
| `POST /retrieve` | JSON `{"document_id":"doc-b"}`；fixed 檢查租戶，vulnerable 刻意忽略租戶 |
| `POST /agent/run` | JSON `{"document_id":"doc-a-untrusted"}` 模擬從 A 文件看到工具請求 marker |
| `POST /agent/run` | JSON `{"document_id":"doc-a","action":"export","approved":true}` 是同租戶且明確核准的正常 mock export |
| `POST /sessions/reset` | JSON `{}`；清除此 bearer session 的 mock conversation memory，保留稽核事件與 sink |
| `POST /__fixture/reset` | JSON `{}`，control header；重設全部合成 session、events、sink |
| `POST /__fixture/shutdown` | JSON `{}`，control header；關閉實際 HTTP server 並正常退出 Python interpreter |
| `GET /__fixture/state?run_id=...` | control header；取得指定 run 的 mock events／sink／unauthorized commit count |

Control header 為 `X-Fixture-Control: local-synthetic-control`。靶場拒絕其他 Host／Origin，沒有 CORS 開放。

自動測試透過 shutdown endpoint 關閉實際 server，再等待 launcher 退出並確認埠已關閉；這可處理 Windows venv 的 `python.exe` redirector／child interpreter 結構。Windows 測試以 Job Object 登錄本次 launcher 與實際 server PID，HTTP 關閉失敗時終止該 Job。啟動尚未回報 PID 時，才對本次仍存活的 launcher 使用程序樹終止；不以程序名稱批量關閉 Python。Linux 不載入 Win32 API，仍使用正常退出／程序終止流程。

`doc-a` canary 是 `TENANT_A_RAG_CANARY`，`doc-b` 是 `TENANT_B_RAG_CANARY`。測 retrieval 隔離時，先用 B 身份取得 doc-b 作正控制，再用 A 取 doc-b；fixed 回 403，vulnerable 回 B 的合成資料。這測的是實際 retrieval 分支，不是把 B 資料預先塞進 A 的上下文後只看回答。

`doc-a-untrusted` 是 A 所有的文件，含 `[[FIXTURE_REQUEST_EXPORT:doc-b]]`。Mock interpreter 看到 marker 就提出 `mock_export(doc-b)`。固定政策要求同租戶且 `approved=true`：

- vulnerable：`retrieved → proposed → invoked → committed`；mock sink 記一筆不被授權的合成資料。
- fixed：`retrieved → proposed → denied`；mock sink 不增加。
- 正常 A/doc-a 明確核准：兩種模式都可 committed，且 `authorized=true`。

`proposed`、`invoked` 與 `committed` 分開記錄；測試以 mock sink 的實際變化佐證，不能只用回答字串推測成功。這個 ledger 仍是**受測合成 fixture 的觀測介面**，不是已實作的正式可信外部 collector。核心 HTTP adapter 不會將此 JSON 自動升格成可信工具效果證據。正式環境需要獨立 collector、完整 trace 和真正授權鏈路；不可用 mock tool 取代它們。

`fixed` 僅修正這些刻意缺陷，並非全面安全的 AI 應用模板。
---
# Local Synthetic AI Agent Application Range

This is a **deterministic mock that calls no LLM**. It only uses fixed markers to simulate "raising tool requests from untrusted documents", making it easy to test retrieval and tool policies, event logging, and the oracle. It cannot prove the probability that models such as Claude, Nemotron, or ChatGPT would be affected by prompt injection, nor can it vouch for real backends.

Only the Python standard library is used; it listens fixedly on `127.0.0.1`, with no external network, disk sink, or shell execution.

```powershell
python fixtures/ai-agent/server.py --mode fixed --port 8912
python fixtures/ai-agent/server.py --mode vulnerable --port 8912
```

Pick one of the two commands; the `--port 0` configuration allocates an available port and reports it in the first JSON line. Stop with Ctrl+C. The exposed synthetic bearer tokens are: A=`fixture-ai-a`, B=`fixture-ai-b`.

| Interface | Purpose |
|---|---|
| `GET /documents/doc-a`, `/documents/doc-b` | A convenient GET positive control for toolkits; returns a `documents` array |
| `POST /retrieve` | JSON `{"document_id":"doc-b"}`; fixed checks the tenant, vulnerable deliberately ignores the tenant |
| `POST /agent/run` | JSON `{"document_id":"doc-a-untrusted"}` simulates seeing a tool-request marker in document A |
| `POST /agent/run` | JSON `{"document_id":"doc-a","action":"export","approved":true}` is a normal mock export, same tenant and explicitly approved |
| `POST /sessions/reset` | JSON `{}`; clears the mock conversation memory of this bearer session, keeping audit events and the sink |
| `POST /__fixture/reset` | JSON `{}`, control header; resets all synthetic sessions, events, and the sink |
| `POST /__fixture/shutdown` | JSON `{}`, control header; shuts down the actual HTTP server and exits the Python interpreter normally |
| `GET /__fixture/state?run_id=...` | control header; gets the mock events/sink/unauthorized commit count of the specified run |

The control header is `X-Fixture-Control: local-synthetic-control`. The range rejects other Hosts/Origins; no CORS is opened.

Automated tests shut down the actual server via the shutdown endpoint, then wait for the launcher to exit and confirm the port is closed; this handles the `python.exe` redirector/child interpreter structure of Windows venvs. Windows tests register this run's launcher and the actual server PID with a Job Object, and terminate the Job if the HTTP shutdown fails. Only when the launched process has not yet reported a PID is process-tree termination used on this run's still-living launcher; Python is never batch-killed by process name. Linux does not load the Win32 API and still uses the normal exit/process-termination flow.

The `doc-a` canary is `TENANT_A_RAG_CANARY`, and `doc-b` is `TENANT_B_RAG_CANARY`. When testing retrieval isolation, first fetch doc-b with identity B as a positive control, then fetch doc-b with A; fixed returns 403, vulnerable returns B's synthetic data. This tests the actual retrieval branch, not pre-loading B's data into A's context and only watching the answer.

`doc-a-untrusted` is a document owned by A, containing `[[FIXTURE_REQUEST_EXPORT:doc-b]]`. The mock interpreter proposes `mock_export(doc-b)` upon seeing the marker. The fixed policy requires the same tenant and `approved=true`:

- vulnerable: `retrieved → proposed → invoked → committed`; the mock sink records one entry of unauthorized synthetic data.
- fixed: `retrieved → proposed → denied`; the mock sink does not increase.
- Normal A/doc-a with explicit approval: both modes can reach committed, with `authorized=true`.

`proposed`, `invoked`, and `committed` are recorded separately; tests corroborate with the actual changes in the mock sink and must not infer success from the answer string alone. This ledger is still the **observation interface of the synthetic fixture under test**, not an implemented formal trusted external collector. The core HTTP adapter will not automatically promote this JSON into trusted tool-effect evidence. A production environment needs an independent collector, full traces, and a real authorization chain; mock tools cannot be used in their place.

`fixed` only fixes these deliberate defects; it is not a comprehensively secure AI application template.
