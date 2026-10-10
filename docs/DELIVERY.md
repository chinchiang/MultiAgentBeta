# 0.2.1 交付範圍與原計畫對照

0.2.0 接續 0.1.0，補上隔離 worker、PostgreSQL 整合、動態工具 adapter、fixture 重置、副作用收集、標準目錄及控制台工作台；0.2.1 再加入盲審 matching 工具、逐端點 header 清單與多輪審查修正（最近一輪見 [VALIDATION.md](VALIDATION.md) 的「2026-10-10 深入審查修正」）。使用者已指定先完成工程與本地整合，真實三模型端點尚未準備。

「已實作」與「已驗證」分開記錄。實際測試結果以 [VALIDATION.md](VALIDATION.md) 和附帶的 JUnit XML 為準；程式存在本身不等於模型或工具的效果已被證明。

| 階段 | 工程交付 | 外部驗收界線 |
|---|---|---|
| P0 | schema v2、逐 Agent 模型、禁止 fallback、四類 provider SDK 合成傳輸契約、固定相依套件版本（npm 鎖定檔含 integrity 雜湊；Python 鎖定檔逐項釘版本並附發布 hash，安裝以 --require-hashes 驗證）、image/rule/database 雜湊、授權來源 | 真實 Claude/OpenAI/Nemotron 型號、額度及用量待端點驗收 |
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

準備確切型號、端點與 VIBEAUDIT_* 憑證環境變數，先跑每端點契約，再以隔離 staging 及合成資料跑完整流程。最後才在人工核定、按專案切分且未公開的測試集執行七組公平預算比較。人工核定可用 0.2.1 附帶的盲審 matching 工具（`python -m vibe_audit.benchmark_matching`，用法見 benchmarks/README.md）產生盲審工作表、記錄兩位 reviewer 裁定並回填 gold；工具只記錄裁定宣告，審核本身仍須由真人完成。未知用量、未完成及缺少觀測不能作零成本或通過處理。

---

# 0.2.1 Delivery Scope Compared with the Original Plan

0.2.0 continues from 0.1.0, adding the isolated worker, PostgreSQL integration, dynamic tool adapters, fixture reset, side-effect collection, the standards catalog and the console workbench; 0.2.1 adds the blind-review matching tool, per-endpoint header lists and several rounds of review fixes (the latest is "2026-10-10 in-depth review fixes" in [VALIDATION.md](VALIDATION.md)). The user has specified completing the engineering and local integration first; the real three-model endpoints are not yet prepared.

"Implemented" and "verified" are recorded separately. Actual test results are governed by [VALIDATION.md](VALIDATION.md) and the accompanying JUnit XML; the mere existence of code does not mean the effects of models or tools have been proven.

| Phase | Engineering deliverables | External acceptance boundary |
|---|---|---|
| P0 | schema v2, per-Agent models, fallback forbidden, synthetic transport contracts for the four provider SDK types, pinned dependency versions (the npm lockfile includes integrity hashes; the Python lockfile pins versions item by item and carries release hashes, with installation verified via --require-hashes), image/rule/database hashes, license sources | Real Claude/OpenAI/Nemotron model names, quotas and usage await endpoint acceptance |
| P1 | LangGraph, PostgreSQL job ledger (recovery follows the run records and the ledger, not LangGraph checkpoints), atomic commits, an independent supervisor, persistent leases, network revocation before stopping, loopback UI, settings, SSE | Local single-user; no multi-user SaaS or cross-host worker fleet commitments |
| P2 | Private read-only staging, three first-pass reviews of the same core questions, parallel static tools, one round of Challenger, program citations, a union of the minority findings, Semgrep/Gitleaks/OSV runners | Program summaries are capped; model quality and deep analysis of arbitrary frameworks cannot be inferred from contract tests |
| P3 | Threat/Requirement gates, version freezing, traceability, ZAP/Schemathesis/Playwright, login/logout fixtures, positive controls and oracles | ZAP is an approved-path requestor + passive; Schemathesis uses explicit examples; Playwright is API flows, not arbitrary exploration, full-site fuzzing or arbitrary browser scripts |
| P4 | promptfoo local eval, PyRIT targets, a registrable fixture protocol, independent effect collectors/sinks, five resets, separation of proposal/rejection/invocation/side effects | mock success does not mean real backend authorization is correct; a real target must provide trustworthy observations, otherwise blocked/inconclusive |
| P5 | Web/JSON/Markdown/SARIF, linked retests, TS/Python synthetic ranges, a seven-group budget comparison runner, ground-truth format, version locking and acceptance | Paid model comparisons were not executed; no claims of bias-reduction, detection-rate or cost improvement. Full-scale production deployment and independent penetration review require separate acceptance |

## Execution Boundaries

- The demo is fully synthetic and calls no models or external targets; the three role names are not results from three model vendors.
- live must use PostgreSQL and Linux Docker. Windows natively provides the console and the demo; live services and workers run in WSL2.
- Source code is mounted only to the white-box worker. The black box uses a different UID, with no sources, target credentials or Docker socket, and network none.
- Every HTTP request goes through an independent supervisor that re-checks the lease, case, identity, exact METHOD/path, target IP, deployment headers and budget, and does not follow redirects.
- Losing contact after submission is outcome_unknown and blocks automatic replay; unconfirmed cleanup cannot show stop as complete.
- A completed assessment means the approved work is finished, not that there are no vulnerabilities or that it is absolutely safe. Capability limitations, actual gaps and safety verdicts are kept separately.
- Container and host administrators are within the trust boundary. Local hashes are not tamper-proof forensic storage and cannot restrict all outbound traffic for external staging.

## Real Model Acceptance

Prepare the exact model names, endpoints and VIBEAUDIT_* credential environment variables; run the per-endpoint contracts first, then run the full flow with an isolated staging environment and synthetic data. Only at the end run the seven-group fair budget comparison on a manually adjudicated, project-partitioned and unpublished test set. For the manual adjudication, the blind-review matching tool shipped with 0.2.1 (`python -m vibe_audit.benchmark_matching`, usage in benchmarks/README.md) produces the blinded worksheet, records the two reviewers' verdicts and backfills the gold; the tool records adjudication declarations only — the review itself must still be performed by real humans. Unknown usage, incomplete runs and missing observations cannot be treated as zero-cost or as passes.
