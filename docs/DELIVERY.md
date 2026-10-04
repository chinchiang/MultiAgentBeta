# 0.2.0 交付範圍與原計畫對照

本版接續 0.1.0，補上隔離 worker、PostgreSQL 整合、動態工具 adapter、fixture 重置、副作用收集、標準目錄及控制台工作台。使用者已指定先完成工程與本地整合，真實三模型端點尚未準備。

「已實作」與「已驗證」分開記錄。實際測試結果以 [VALIDATION.md](VALIDATION.md) 和附帶的 JUnit XML 為準；程式存在本身不等於模型或工具的效果已被證明。

| 階段 | 工程交付 | 外部驗收界線 |
|---|---|---|
| P0 | schema v2、逐 Agent 模型、禁止 fallback、四類 provider SDK 合成傳輸契約、固定依賴版本（npm 鎖定檔含 integrity 雜湊；Python 鎖定檔逐項釘版本並附發布 hash，安裝以 --require-hashes 驗證）、image/rule/database 雜湊、授權來源 | 真實 Claude/OpenAI/Nemotron 型號、額度及用量待端點驗收 |
| P1 | LangGraph、PostgreSQL job ledger（恢復依 run 紀錄與 ledger，不讀 LangGraph checkpoint）、原子提交、獨立 supervisor、持久 lease、撤網先於停止、loopback UI、設定、SSE | 本地單使用者；沒有多人 SaaS 或跨主機 worker fleet 承諾 |
| P2 | 私有唯讀 staging、三份同核心問題初審、並行靜態工具、一輪 Challenger、程式引用、少數發現聯集、Semgrep/Gitleaks/OSV runner | 程式摘要有上限；模型品質與任意 framework 深度分析不能由契約測試推論 |
| P3 | 威脅/Requirement gate、版本凍結、追溯、ZAP/Schemathesis/Playwright、登入/登出 fixture、正控制與 oracle | ZAP 為核准路徑 requestor + passive；Schemathesis 為明確 example；Playwright 為 API 流程，不是任意探索、全站 fuzz 或任意瀏覽器腳本 |
| P4 | promptfoo 本地 eval、PyRIT target、可註冊 fixture protocol、獨立 effect collector/sink、五次重置、提出/拒絕/呼叫/副作用分離 | mock 成功不代表真實後端授權正確；真實 target 必須提供可信觀測，否則 blocked/inconclusive |
| P5 | Web/JSON/Markdown/SARIF、關聯複測、TS/Python 合成靶場、七組預算比較 runner、ground-truth 格式、版本鎖定及驗收 | 未執行付費模型比較；不宣稱減偏、檢出率或成本改善。正式大規模部署及獨立滲透審查須另行驗收 |

## 執行邊界

- demo 完全合成，不呼叫模型或外部靶場；三個角色名稱不是三家模型結果。
- live 必須使用 PostgreSQL 和 Linux Docker。Windows 原生提供控制台與示範；WSL2 中執行 live 服務與 workers。
- 原始碼只掛載給白箱 worker。黑箱使用不同 UID，無來源、目標憑證或 Docker socket，網路為 none。
- 每個 HTTP 請求經獨立 supervisor，重新檢查 lease、案例、身分、精確 METHOD/path、目標 IP、部署 header 和預算，不跟隨 redirect。
- 送出後失聯為 outcome_unknown，阻擋自動重播；未確認清理不能顯示停止完成。
- 完成評估表示核准工作完成，不是沒有漏洞或絕對安全。能力限制、實際缺口與安全判定分開保存。
- 容器與主機管理者屬信任邊界。本地雜湊不是不可竄改法證儲存，也無法替外部 staging 限制全部出網。

## 真實模型驗收

準備確切型號、端點與 VIBEAUDIT_* 憑證環境變數，先跑每端點契約，再以隔離 staging 及合成資料跑完整流程。最後才在人工核定、按專案切分且未公開的測試集執行七組公平預算比較。未知用量、未完成及缺少觀測不能作零成本或通過處理。
