# 盲審 matching 範例：完整走一遍裁定流程

這是一個刻意縮小、可完整重現的範例，示範 `python -m vibe_audit.benchmark_matching` 的 worksheet → 裁定 →（分歧仲裁）→ apply 全流程。隨附 dataset 仍是**合成 fixture**；此範例展示的是工程與稽核軌跡，不是任何模型的效果證據。

附帶資料集 `benchmarks/synthetic-v1.json` 的 gold 已涵蓋全部已知 finding，工作表會是空的；要練習真實裁定，需要這種「runs 回報 gold 之外 finding」的資料，因此另備此例。

## 檔案

| 檔案 | 內容 |
|---|---|
| `example-dataset.json` | 來源資料集：兩個合成樣本（`sqli-login`、`eval-report`），各含一個 gold positive、一個 gold negative，與預先指定的 fixture 回應 |
| `example-results.jsonl` | 對該資料集真實執行一次 `vibe_audit.benchmark`（synthetic、repetitions=1、seed=731）產生的 14 筆紀錄 |
| `example-worksheet.json` | 由上述兩檔產生的盲審工作表：4 個 gold 之外的未知 finding，不含任何組別／模型身分 |
| `reviewer-a.json` | 具名 reviewer alice 的裁定檔，涵蓋全部 4 筆（繫結 worksheet hash） |
| `reviewer-b.json` | 具名 reviewer bob 的裁定檔，涵蓋全部 4 筆，其中 1 筆與 alice 分歧 |
| `arbiter.json` | 第三位 arbiter carol 的部分裁定檔，只裁定那筆分歧 |
| `adjudicated/` | `apply` 的實際輸出：回填後資料集、matching record、重算後 results |

## 情境

| 樣本 | 未知 finding | alice | bob | 結果 |
|---|---|---|---|---|
| sqli-login | `semgrep:sqli-login-py-l6` | matches_positive → `sqli-login:sql-injection-login` | 同 | 一致：回填 gold positive |
| sqli-login | `bandit:b608-login-py-l10` | matches_negative → `sqli-login:safe-parameterized-query` | 同 | 一致：回填 gold negative |
| eval-report | `bandit:b307-report-py-l9` | matches_positive → `eval-report:unsafe-eval-config` | new_positive | 分歧 → arbiter carol 裁定 matches_positive |
| eval-report | `lgtm:py/template-injection-report` | not_a_vulnerability | 同 | 一致：回填 gold negative |

四種 verdict 皆有示範。語意：`matches_positive`／`matches_negative` 表示與既有 gold 項目**同一問題**（不同工具對同一 sink 的不同 ID 是常見來源），必須附上存在於對應 gold 清單且各方一致的 `matched_gold_id`；`new_positive` 是 gold 尚未收錄的真實漏洞；`not_a_vulnerability` 是 gold 尚未收錄的誤報。所有正向 verdict 回填 gold positive，其餘回填 gold negative。

## 重現

```powershell
$env:PYTHONPATH = 'backend'
# 1. 對範例資料集跑一次合成基準（會重現 example-results.jsonl，牆鐘時間欄位除外）
python -m vibe_audit.benchmark --dataset benchmarks/examples/example-dataset.json --output <run-dir> --mode synthetic --repetitions 1 --seed 731 --split test
# 2. 產生盲審工作表（比對隨附 example-worksheet.json）
python -m vibe_audit.benchmark_matching worksheet --dataset benchmarks/examples/example-dataset.json --results benchmarks/examples/example-results.jsonl --output <worksheet.json>
# 3. 先只交兩位 reviewer：apply 會拒絕，要求 arbiter（all-or-nothing 安全欄）
python -m vibe_audit.benchmark_matching apply --dataset benchmarks/examples/example-dataset.json --results benchmarks/examples/example-results.jsonl --reviewer benchmarks/examples/reviewer-a.json --reviewer benchmarks/examples/reviewer-b.json --output-dir <out>
# 4. 補上 arbiter 後成功套用
python -m vibe_audit.benchmark_matching apply --dataset benchmarks/examples/example-dataset.json --results benchmarks/examples/example-results.jsonl --reviewer benchmarks/examples/reviewer-a.json --reviewer benchmarks/examples/reviewer-b.json --arbiter benchmarks/examples/arbiter.json --output-dir <out>
```

步驟 3 預期失敗：`Unresolved disagreements need an arbiter decision for: eval-report/bandit:b307-report-py-l9`。步驟 4 輸出 `{"decisions": 4, "agreed": 3, "arbitrated": 1, "reviewers": ["alice", "bob"]}`。若保留第 1 步的 `report.json`，可在 `apply` 加 `--report` 一併重建報告（附 adjudication 來源與限制說明）。

套用後：兩個樣本的 gold `human_reviewed=true`、`reviewers=["alice","bob","carol"]`；`unadjudicated_ids` 清空、`preview_metrics` 的 precision 可計算；gold 仍為 `synthetic=true`，正式 `metrics` 維持 null——合成 gold 永不晉升效果指標。

## 雜湊繫結與重生成

裁定檔的 `worksheet_hash` 繫結本工作表（dataset + results 內容摘要）。`example-results.jsonl` 的 `measured_wall_seconds` 每次執行都不同；若你重新產生 results，工作表 hash 會改變，隨附的三份裁定檔會**被設計好的檢查拒絕**（worksheet_hash mismatch）——這正是防錯用機制。此時請依新工作表重寫裁定檔的 hash（或改用步驟 1 的輸出從頭走一遍）。裁定檔只是宣告紀錄，工具無法證明具名審核確實發生；正式研究仍須保留 reviewer 原始記錄與 oracle 執行證據。

---
# Blind-review matching example: the adjudication flow end to end

This is a deliberately small, fully reproducible walkthrough of `python -m vibe_audit.benchmark_matching`: worksheet → adjudication → (disagreement arbitration) → apply. The bundled dataset is still a **synthetic fixture**; this example demonstrates engineering and an audit trail, not evidence of any model's effect.

The bundled dataset `benchmarks/synthetic-v1.json` covers every known finding in its gold, so its worksheet comes out empty; practicing real adjudication needs data where runs report findings outside gold, hence this example.

## Files

| File | Content |
|---|---|
| `example-dataset.json` | The source dataset: two synthetic samples (`sqli-login`, `eval-report`), each with one gold positive, one gold negative, and pre-specified fixture responses |
| `example-results.jsonl` | The 14 records produced by one real run of `vibe_audit.benchmark` on that dataset (synthetic, repetitions=1, seed=731) |
| `example-worksheet.json` | The blinded worksheet built from the two files above: 4 unknown findings outside gold, with no arm or model identity |
| `reviewer-a.json` | Named reviewer alice's adjudication file covering all 4 decisions (bound to the worksheet hash) |
| `reviewer-b.json` | Named reviewer bob's adjudication file covering all 4 decisions, disagreeing with alice on 1 |
| `arbiter.json` | A third arbiter carol's partial file deciding only that disagreement |
| `adjudicated/` | The actual `apply` outputs: the backfilled dataset, the matching record, and the recomputed results |

## Scenario

| Sample | Unknown finding | alice | bob | Outcome |
|---|---|---|---|---|
| sqli-login | `semgrep:sqli-login-py-l6` | matches_positive → `sqli-login:sql-injection-login` | same | Agreed: backfilled as a gold positive |
| sqli-login | `bandit:b608-login-py-l10` | matches_negative → `sqli-login:safe-parameterized-query` | same | Agreed: backfilled as a gold negative |
| eval-report | `bandit:b307-report-py-l9` | matches_positive → `eval-report:unsafe-eval-config` | new_positive | Disagreement → arbiter carol: matches_positive |
| eval-report | `lgtm:py/template-injection-report` | not_a_vulnerability | same | Agreed: backfilled as a gold negative |

All four verdicts are demonstrated. Semantics: `matches_positive`/`matches_negative` mean "the same issue as an existing gold entry" (different tools' IDs for the same sink are the usual source) and require a `matched_gold_id` present in the corresponding gold list and consistent across owners; `new_positive` is a real vulnerability not yet in gold; `not_a_vulnerability` is a false positive not yet in gold. Every positive verdict backfills a gold positive; the others backfill gold negatives.

## Reproducing

```powershell
$env:PYTHONPATH = 'backend'
# 1. Run one synthetic benchmark over the example dataset (reproduces example-results.jsonl, except wall-time fields)
python -m vibe_audit.benchmark --dataset benchmarks/examples/example-dataset.json --output <run-dir> --mode synthetic --repetitions 1 --seed 731 --split test
# 2. Build the blinded worksheet (compare against the committed example-worksheet.json)
python -m vibe_audit.benchmark_matching worksheet --dataset benchmarks/examples/example-dataset.json --results benchmarks/examples/example-results.jsonl --output <worksheet.json>
# 3. Submit only the two reviewers: apply refuses and demands an arbiter (the all-or-nothing guard)
python -m vibe_audit.benchmark_matching apply --dataset benchmarks/examples/example-dataset.json --results benchmarks/examples/example-results.jsonl --reviewer benchmarks/examples/reviewer-a.json --reviewer benchmarks/examples/reviewer-b.json --output-dir <out>
# 4. Succeed with the arbiter added
python -m vibe_audit.benchmark_matching apply --dataset benchmarks/examples/example-dataset.json --results benchmarks/examples/example-results.jsonl --reviewer benchmarks/examples/reviewer-a.json --reviewer benchmarks/examples/reviewer-b.json --arbiter benchmarks/examples/arbiter.json --output-dir <out>
```

Step 3 is expected to fail with `Unresolved disagreements need an arbiter decision for: eval-report/bandit:b307-report-py-l9`. Step 4 prints `{"decisions": 4, "agreed": 3, "arbitrated": 1, "reviewers": ["alice", "bob"]}`. If you keep step 1's `report.json`, pass `--report` to `apply` to rebuild the report alongside (with adjudication provenance and a limitation note).

After applying: both samples' gold gets `human_reviewed=true` and `reviewers=["alice","bob","carol"]`; `unadjudicated_ids` is empty and `preview_metrics` precision becomes computable; the gold is still `synthetic=true`, so the formal `metrics` stay null — synthetic gold can never be promoted to efficacy metrics.

## Hash binding and regeneration

The adjudication files' `worksheet_hash` binds to this worksheet (a digest of the dataset plus results content). `example-results.jsonl` contains `measured_wall_seconds`, which differs on every run; if you regenerate the results, the worksheet hash changes and the three committed adjudication files are **rejected by design** (worksheet_hash mismatch) — that is exactly the anti-misuse mechanism. In that case, rewrite the files' hash from the new worksheet (or redo the walkthrough from step 1's output). The adjudication files are declaration records only; the tool cannot prove the named reviews occurred. A formal study must still retain the reviewers' original records and oracle execution evidence.
