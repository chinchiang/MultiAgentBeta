# 本地合成 Web/API 靶場

這是工具包的刻意缺陷示範，只包含假資料與記憶體 session，不能當成真實後端授權驗證。固定只監聽 `127.0.0.1`，沒有外部網路、磁碟寫入或重型依賴。需要 Node.js 24，以內建 TypeScript type stripping 執行。

```powershell
node fixtures/web-api/server.ts --mode fixed --port 8911
node fixtures/web-api/server.ts --mode vulnerable --port 8911
```

兩個命令擇一執行；`--port 0` 由系統配置可用埠，首行 JSON 會提供 `origin`。停止按 Ctrl+C。

所有 API 回應標記 `synthetic: true`，靶場僅接受自己的 exact Host／Origin，沒有 CORS 放行。`GET /` 提供簡單說明頁。

| 介面 | 行為 |
|---|---|
| `GET /orders/order-a` | 租戶 A 的假訂單，canary 為 `TENANT_A_ORDER_CANARY` |
| `GET /orders/order-b` | 租戶 B 的假訂單，canary 為 `TENANT_B_ORDER_CANARY` |
| `GET /me` | 目前合成 session 的使用者、租戶、角色 |
| `POST /auth/login` | JSON `{"username":"alice","password":"synthetic-alice"}`；Bob 對應 `bob`、`synthetic-bob` |
| `POST /auth/logout` | JSON `{}`；fixed 撤銷此 bearer token；vulnerable 只回覆登出成功但仍接受 token |
| `POST /__fixture/reset` | JSON `{}`，需要 `X-Fixture-Control: local-synthetic-control`；清空事件並重設初始 session |
| `GET /__fixture/state` | 同一 control header，查看合成事件及 session 數量 |
| `POST /__fixture/shutdown` | JSON `{}`，同一 control header；完成回應後正常關閉 HTTP server 並退出 |

初始 bearer tokens 是公開的假憑證：A=`fixture-web-a`、B=`fixture-web-b`。設定本地測試用環境變數：

```powershell
$env:VIBEAUDIT_FIXTURE_A = 'fixture-web-a'
$env:VIBEAUDIT_FIXTURE_B = 'fixture-web-b'
```

工具包 auth profiles 可分別引用這兩個環境變數。用 B 身份讀 `/orders/order-b` 是 positive control；再用 A 身份讀同一路徑，vulnerable 會回傳 B canary，fixed 回 403。這證明本地 fixture 的 BOLA 分支可辨識。

登出測試以 `alice` 登入並擷取 session，先成功讀 `/orders/order-a`（含 `TENANT_A_ORDER_CANARY`），對 `/auth/logout` POST，再以同一個 session 重讀 `/orders/order-a`；vulnerable 是 200 且仍含 canary，fixed 是 401。每一步使用新 HTTP 請求，session 只由 supervisor 保存。內建的 `synthetic-web-v1` fixture profile 以原生 HTTP sequence 執行此流程（`fixture_protocol.py`）；外部工具無法使用擷取的 session，指定它們時會 blocked。

`fixed` 只修正以上兩個刻意缺陷，並非全面安全的應用模板。

`bola-case.json` 是核心 HTTP adapter 的案例範例。使用時在 run 中允許 `GET /orders/order-b`，auth profiles ID 必須為 `tenant-a`、`tenant-b`，且威脅模型要包含 `T-BOLA` 與 `R-TENANT-ISOLATION` 的對應需求。Compiler 會補來源／威脅版本雜湊；不要手動偽造 gate receipt。此檔本身不是已完成的測試結果。
---
# Local Synthetic Web/API Range

This is the toolkit's deliberate-defect demo, containing only fake data and in-memory sessions; it cannot be treated as real backend authorization verification. It listens only on `127.0.0.1` by design, with no external network, disk writes, or heavy dependencies. Node.js 24 is required, running with built-in TypeScript type stripping.

```powershell
node fixtures/web-api/server.ts --mode fixed --port 8911
node fixtures/web-api/server.ts --mode vulnerable --port 8911
```

Run one of the two commands; `--port 0` lets the system assign an available port, and the first JSON line provides `origin`. Stop with Ctrl+C.

All API responses are marked `synthetic: true`; the range accepts only its own exact Host/Origin, and no CORS is allowed. `GET /` provides a simple description page.

| Interface | Behavior |
|---|---|
| `GET /orders/order-a` | Tenant A's fake order, canary `TENANT_A_ORDER_CANARY` |
| `GET /orders/order-b` | Tenant B's fake order, canary `TENANT_B_ORDER_CANARY` |
| `GET /me` | The current synthetic session's user, tenant, and roles |
| `POST /auth/login` | JSON `{"username":"alice","password":"synthetic-alice"}`; Bob corresponds to `bob`, `synthetic-bob` |
| `POST /auth/logout` | JSON `{}`; fixed revokes this bearer token; vulnerable only replies that logout succeeded but still accepts the token |
| `POST /__fixture/reset` | JSON `{}`, requires `X-Fixture-Control: local-synthetic-control`; clears events and resets the initial session |
| `GET /__fixture/state` | Same control header, to view synthetic event and session counts |
| `POST /__fixture/shutdown` | JSON `{}`, same control header; after completing the response, shuts down the HTTP server and exits normally |

The initial bearer tokens are public fake credentials: A=`fixture-web-a`, B=`fixture-web-b`. Set the environment variables for local testing:

```powershell
$env:VIBEAUDIT_FIXTURE_A = 'fixture-web-a'
$env:VIBEAUDIT_FIXTURE_B = 'fixture-web-b'
```

The toolkit's auth profiles can reference these two environment variables respectively. Reading `/orders/order-b` as identity B is a positive control; then reading the same path as identity A, vulnerable returns B's canary and fixed returns 403. This proves the local fixture's BOLA branch is identifiable.

The logout test logs in as `alice` and captures the session, first successfully reads `/orders/order-a` (containing `TENANT_A_ORDER_CANARY`), POSTs to `/auth/logout`, then re-reads `/orders/order-a` with the same session; vulnerable gives 200 and still contains the canary, fixed gives 401. Each step uses a fresh HTTP request, and the session is held only by the supervisor. The built-in `synthetic-web-v1` fixture profile runs this flow as a native HTTP sequence (`fixture_protocol.py`); external tools cannot use the captured session, and specifying them is blocked.

`fixed` only fixes the two deliberate defects above; it is not a comprehensively secure application template.

`bola-case.json` is a case example for the core HTTP adapter. To use it, allow `GET /orders/order-b` in the run, the auth profile IDs must be `tenant-a` and `tenant-b`, and the threat model must include the requirements mapped to `T-BOLA` and `R-TENANT-ISOLATION`. The compiler fills in the source/threat version hashes; do not manually forge the gate receipt. This file itself is not a completed test result.
