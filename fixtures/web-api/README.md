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
