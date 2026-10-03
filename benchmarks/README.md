# 比較實驗：先驗證工程，再驗證效果

此 runner 已能排程、執行合成回應、執行本地傳統 AST 基線、計算指標並產出可追溯 JSON。隨附資料是 **合成 fixture，gold 待人工審核**。它不能證明任何真實模型更準確或多模型降低偏誤。

```powershell
$env:PYTHONPATH = 'backend'
python -m vibe_audit.benchmark --mode synthetic --output benchmarks/results-synthetic
python -m vibe_audit.benchmark --mode local_tools --output benchmarks/results-local
```

`synthetic` 排程中的每個輸出皆來自預先指定的 fixture。`local_tools` 真的對 fixture 的 Python 文字執行標準函式庫 AST 分析，不執行程式碼、HTTP、模型或 shell；它只偵測 eval／exec 呼叫，是狹窄的傳統靜態基線，不能冒稱 Semgrep 或完整 SAST。其他模型組均產生明確 blocked 紀錄。`live` 已有可執行 provider 與工具注入接口，缺少明確 profile／policy 時才 blocked；沒有使用真實金鑰驗證效果。

## 比較組與預算

七組：傳統工具、單模型 A／B／C、同模型 A 三次、三模型獨立審查、三模型初審後一次 debate。A／B／C 是合成角色，沒有假稱 Claude、GPT 或 Nemotron。

每個 project/sample/repetition 下七組使用相同 token、牆鐘時間、請求與模型呼叫上限，並以固定種子打散組別順序。三人組不能取得三倍總預算。單次步驟均分組別上限；debate 的額外一輪也占用同一總預算。這是相同預算上限，不保證實際花費相同。傳統工具合理地使用零模型 token。

各組初審接收相同 input，不能看到 gold 或其他初審輸出；每步記錄 input hash 及封存輸出 hash。只有 debate 最後一步能看到封存初審。異質獨立組保留候選聯集，不用多數票抹去少數意見；候選被保留不代表漏洞成立。合成 debate 刻意包含保留或丟失少數真陽性的案例，以驗證量測是否抓得出此現象。

## 資料與人工 gold

資料以完整專案及 project family 分為 train／validation／test；相關 fork 或版本不能跨 split。CLI 預設只跑 test，訓練／調參與最終測試必須分開。這項檢查不能證明資料未出現在模型預訓練中。

正式 gold 需要兩位獨立且具名的人工 reviewer、明確 positive／negative issue IDs、oracle_verified 與 evidence references，並標示 synthetic=false。聲明本身不代替人工工作；正式研究還須保留 reviewer 原始記錄、分歧仲裁、oracle 執行證據與不可變樣本 digest。模型的未知 finding 必須先做人類盲審 matching，不能用標準分類 ID 直接當成漏洞同一性。

已知限制：runner 不提供人工裁定流程。human_reviewed、reviewers 與 oracle_evidence 是宣告欄位，只檢查格式（至少兩個不同姓名、證據清單非空），不能證明審核確實發生；未知 finding 列於 `unadjudicated_ids`，沒有盲審 matching 介面可回填為 TP／FP，因此 precision 維持 null。上述審核、分歧仲裁與 matching 須在工具外完成後再產生新的 gold。

隨附 gold 的 human_reviewed=false，所有品質指標只放在 `preview_metrics`，正式 `metrics=null`。模型組在 local_tools／live 的 blocked 情境不填零品質分數，以免把未測當成漏報。

## 指標定義與限制

- Precision = TP/(TP+FP)，Recall = TP/(TP+FN)。沒有分母時為 null。出現尚未人工裁定的未知 finding 時 precision 為 null，另列 unmatched IDs，不能偷偷算成真或假陽性。
- Common miss = 所有獨立初審都未發現的 gold positive / 全部 gold positive。僅有一份初審時為 null。
- Minority retention = 只被一位初審找到、且由 gold 確認為真的項目中，最終仍保留的比例。沒有適用項目時為 null。
- Reproduce = 有 oracle 重現記錄的 TP / 全部 TP。合成重現只代表 fixture 的標記，不是實際目標 exploit。
- Completion 分開記錄 completed/incomplete/blocked；耗盡預算或缺回應不得算完整。
- 每組記錄 tokens、requests、model calls、宣告 latency、實測 runner wall time 與 cost。未知價格為 null，合成 token/latency 不冒充實際模型用量。

彙總的品質指標只取 completed 紀錄中有定義樣本的 macro mean；incomplete 紀錄的部分結果仍逐筆保留，但不進入平均，只計入 completion。completion 以每組全部排程計算，blocked 與 incomplete 都算未完成（arms 下另有 `completion` 欄）；配對的 completion 差值也直接比較兩方狀態，blocked 的一方不會讓比較消失。原始 TP/FP/FN 仍逐筆保留。以 project/sample/repetition 配對 single A 產生差值，任一方未完成時只比較 completion，沒有自動做顯著性或降低偏誤的推論。正式比較應先註冊主要指標，以專案為 cluster 做配對重抽樣／信賴區間，不能將同一專案的多次重跑視為獨立樣本。效果研究尚未執行，因此本程式沒有假造 p 值或模型優勢。

## 真模型效果驗證前仍需提供

精確模型、核准資料政策／預算、可重置隔離目標、相同工具能力、真實用量與費用來源、兩人審核 gold／oracle evidence。CLI 沒有設定時保留完整 blocked 排程與原因，沒有省略未測的組別。

## Live runner 接口

`run_live_benchmark(..., profiles={a:...,b:...,c:...}, model_policy={data_policy:...,allowed_model_origins:[...]}, tool_runner=..., model_runner=...)` 是 async API；同步程式使用 `run_benchmark(mode='live', ...)`。`model_runner(profile, system, payload, policy)` 預設使用現有 `providers.generate_json`，因此沿用精確端點、憑證環境變數、JSON schema、輸出與總 token 檢查及有限重試。模型設定完整保存；同模型組重複 A，異質組需要三個不同配置與模型家族；debate 最後由 A 使用匿名化的初審結果仲裁。

可信 async `tool_runner(input_data, budget)` 必須回傳 `BENCHMARK_OBSERVATION_SCHEMA`。可在 host 設定中連接固定 sandbox 的 Semgrep／OSV／Gitleaks adapter，不可讓 dataset 或模型指定任意 Python import、shell 或工具。工具只能在分配到的時間與請求預算內執行；adapter 本身仍須在每次副作用前預留預算。超時或契約錯誤時所有依賴該工具輸出的組都 blocked，並保守保留資源上限。回傳的 finding ID 必須按人工 matching 規則正規化，不能把工具的 rule ID 當成漏洞實例 ID。

每組共享同一 paired sample 的已封存 tool_context；其用量在每組預算中扣除，剩下額度再均分模型步驟。每個模型步驟至少要分到 provider 的重試次數（`MAX_ATTEMPTS`），各組才有相同的 schema 修正機會；live 預設 `max_model_calls` 因此是 8（debate 四步 × 2），傳入不足的預算會直接拒絕，工具用掉呼叫次數而不足時該步驟 blocked。工具實際每個 pair 只執行一次，報告也保留 `shared_tool_contexts`；各組用量相加不能當作實際總工具花費。所有獨立初審 payload 一致且不包含 gold；debate 才取得匿名初審。模型無法自行宣布動態重現，只有可信工具／oracle adapter 可提供 reproduced_ids；未做重現時 reproduce_rate 為 null。

CLI 可用 `--mode live --config path/to/benchmark-config.json`，config 只接受 `profiles` 與 `model_policy`。profiles 的 a/b/c 各自符合既有 ModelProfile，金鑰只能用 `VIBEAUDIT_*` 環境變數參照。CLI 預設傳統工具仍是本地 AST；整合 sandbox 工具時使用 async API 注入。測試用注入 adapter 可驗證調度及預算，不代表真實模型品質。
