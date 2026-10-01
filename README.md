# Vibe Audit 0.2.0

Multi-Agent 資安測試工具包：**白箱獨立審查 → 威脅建模 → 案例與 Oracle → 隔離黑箱 → 證據裁決**。

AI Commander 負責派工；程式 Harness 強制範圍、階段、權限、預算與證據。三個 reviewer 可分別指定 Claude、OpenAI、Nemotron 或本地端點；沒有靜默 fallback，也不用多數票決定漏洞。

本次依使用者要求先交付工程與本地整合。**沒有實際三模型端點或付費效果實驗；不宣稱減偏、檢出率或成本改善。** 本地測試使用明確標示的合成模型/靶場；真實工具與隔離基礎設施的驗收另列於 [驗證紀錄](docs/VALIDATION.md)。

## 開啟控制台

Windows 需 Python 3.12+ 與 Node 24。第一次安裝會下載固定依賴：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup.ps1
powershell -ExecutionPolicy Bypass -File scripts/start-local.ps1
```

開啟啟動時終端機印出的網址（`http://127.0.0.1:8000/#token=…`），先選「合成示範」。權杖只用來建立 session，同一瀏覽器重新整理不需再帶；後端重啟會產生新權杖，可用 `VIBEAUDIT_SESSION_TOKEN`（32–256 個 URL-safe 字元）固定。控制台可保存專案/模型設定、檢視三份審查、威脅/需求/案例追溯、證據與用量，匯出 JSON/Markdown/SARIF，建立保留原始關聯的修補複測。

Windows 原生不執行 live 隔離掃描。真實工作流請在 Linux 或 WSL2 依 [Linux 操作指南](docs/LINUX_SETUP.md) 啟動，使用 PostgreSQL、Docker、已準備的模型端點與使用者提供的隔離 staging。

## 能力與邊界

| 層次 | 交付 |
|---|---|
| 指揮核心 | FastAPI + LangGraph、PostgreSQL checkpoint/job ledger、獨立 supervisor/lease、恢復與停止 |
| 白箱 | 同範圍三模型隔離初審、證據聯集、一輪 Challenger、來源引用驗證、Semgrep/Gitleaks/OSV |
| 威脅模型 | 自有 JSON、資產/資料流/信任邊界/Requirement、版本與來源、462 個 canonical 標準 IDs |
| Web 黑箱 | 受控 HTTP、ZAP requestor/passive、Schemathesis explicit examples、Playwright API、登入/登出 fixture |
| AI 黑箱 | promptfoo 本地 eval、PyRIT target、reset/cleanup protocol、五次試验、独立工具事件與 sink 收據 |
| 結果 | 證據雜湊/歸屬驗證、狀態分級、缺口、追溯工作台、關聯複測、三種匯出 |
| 比較評估 | 七組公平預算 runner、合成 plumbing 與本地 AST 基線、人工 ground-truth 格式；沒有真模型效果結論 |

工具整合使用有界、固定案例。此版沒有任意站點探索、全站主動 fuzz、任意瀏覽器腳本、任意 shell、自動修補/部署、多人 SaaS 或法證級不可竄改儲存。查看 [完整交付對照](docs/DELIVERY.md)。

## 安全政策

- 沒有完整三模型初審、有效威脅模型、追溯 Requirement 和 Oracle，黑箱不能取得權限。
- 原始碼只掛載到白箱 worker；黑箱使用不同 UID，無 Docker socket、主機機密或原始碼，容器網路為 none。
- 所有目標請求經獨立 broker；精確 METHOD/path、IP、身分、案例 hash、lease、預算和可選部署 header 每次檢查。redirect 拒絕。
- 憑證只能以 VIBEAUDIT_* 環境變數名称引用；目標憑證由 supervisor 注入，不交給工具。local_only 僅接受明確 loopback 模型端點。
- 白箱 raw staging 與模型用脫敏快照分開。來源讀取有上限，脫敏及路由抽取是啟發式；未讀檔案和未知業務規則會保留缺口。
- 文字宣稱、HTTP 狀態碼、scanner exit 0、模型共識都不能單獨證明安全。控制或觀測失敗不能判為通過。
- 送出後中斷標示 outcome_unknown，不自動重播。停止先撤銷網路；未確認清理仍顯示未完成。
- loopback 單使用者 session：建立 session 需要啟動權杖（同機其他程序無法自行取得 session 再探測模型或讀取證據），另有 Host/Origin/CSRF 防護；受測文字以不可信資料呈現。不要將控制台直接公開到網際網路。

容器、資料庫與控制程序管理者屬信任邊界；本工具無法限制外部 staging 的全部出網，也不能保證找出所有漏洞。

## 文件與開發

- [部署與設定](docs/LINUX_SETUP.md)
- [架構與方法](docs/ARCHITECTURE.md)
- [API 與模組契約](IMPLEMENTATION.md)
- [交付對照](docs/DELIVERY.md)／[驗證紀錄](docs/VALIDATION.md)
- [模型減偏比較設計](benchmarks/README.md)
- [來源與授權](docs/SOURCES.md)／[NOTICE](NOTICE)
- [合成範例報告](docs/sample-report.md)

```powershell
$env:PYTHONPATH = 'backend'
.venv/Scripts/python.exe -m pytest tests -q
cd frontend
npm.cmd run build
```

沒有 Linux/PostgreSQL/固定映像的測試環境，對應整合測試會明確 skip。不能將 skipped 當作驗證通過。核心 Apache-2.0；外部工具、規則、模型與標準內容各保留原授權。
