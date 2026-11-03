# AGENTS.md

Vibe Audit 0.2.1：以證據把關的多模型資安測試工作台。Python 後端在 `backend/vibe_audit`，React 控制台在 `frontend/`。架構見 README 的「系統架構與流程」與 `docs/ARCHITECTURE.md`；API 與模組契約見 `IMPLEMENTATION.md`。

## 回覆語言

以正體中文、臺灣慣用語回覆。專有名詞中英並列，例如：單一來源（single source of truth）。只有非用英文不可的地方才用英文：程式碼、指令、識別碼、檔案路徑，以及 repo 慣例要求英文的訊息。

## 常用指令

一律在 repo 根目錄執行；catalogs、fixtures 與建置好的介面不在 Python 套件內。

```sh
python -m pip install --require-hashes -r requirements.lock.txt   # 固定版本並檢查雜湊
PYTHONPATH=backend python -m pytest tests -q -rs                  # -rs：逐項看 skip 原因
python scripts/package-release.py --manifest-only                 # 任何被追蹤的檔案變更後執行
python scripts/package-release.py --check                         # CI 會跑
python scripts/redact-receipts.py --check                         # docs/ 裡的收據不得含主機或帳號名稱
python -m ruff check backend tests scripts                        # lint：未使用的名稱與匯入、語法錯誤、bugbear（規則在 pyproject.toml）
sh scripts/contract-smoke.sh                                      # 對真實 loopback 後端跑控制台的 SSR／API 契約 smoke（CI 會跑）
cd frontend && npm ci && npm run typecheck && npm test && npm run check:i18n && npm run check:messages && npm run build   # dist/ 有提交進版控；npm test 跑 tests/ 的 vitest 單元與元件測試；check:i18n 找出沒有英文對照的介面中文；check:messages 比對前後端讀訊息對照表的結果
git add -N frontend/dist && git diff --exit-code -- frontend/dist # CI：dist 必須與原始碼建置結果一致
python -m pip install --require-hashes -r requirements.mutation.lock.txt && python scripts/mutation-test.py   # 突變測試（Linux）：閘門與解析模組的每個突變都要被測試抓到
```

## 規則

- `source-manifest.sha256` 記錄每個被追蹤檔案的雜湊，只能用腳本重產，不可手改。
- `.gitattributes` 設定 `* -text`：保留每個檔案原本的換行（`scripts/package-release.py` 等檔案是 CRLF），shell script 維持 LF。
- README.md、docs/ARCHITECTURE.md、IMPLEMENTATION.md、docs/VALIDATION.md 等文件為中英雙語（中文段與英文段），兩段要一起改。中文使用正體中文與臺灣慣用語。
- tests/test_bilingual_docs.py 檢查每份說明文件都是「中文段、`---`、英文段」且標題數對齊，文件標題的版本號要等於 pyproject.toml。
- 控制台為中英雙語：每段可見文字都在使用處寫成 `t('中文','English')`，模組層級的對照表用 `frontend/src/i18n.ts` 的 `labels()`。
- 引擎自己寫的英文訊息（錯誤、執行紀錄、缺口、判定說明、示範內容）要在 `backend/vibe_audit/messages.py` 加中文；`tests/test_error_messages.py` 會找出漏掉的，控制台以 `say()` 顯示。模型、掃描器、目標與操作者的文字不翻譯。
- 權威驗證在 `domain.py`、`contracts.py`、`policy.py` 與 `docs/run-input.schema.json`；文件要與它們一致。
- skip 不等於通過，不要在 docs/VALIDATION.md 把 skip 記成已驗證。
- JUnit 收據放進 docs/ 前先跑 `python scripts/redact-receipts.py`，再跑 `python scripts/summarize-validation.py`。
- `.claude/`、本檔與 `CLAUDE.md` 由 `scripts/package-release.py` 排除在發佈檔之外。`CLAUDE.md` 只有一行 `@AGENTS.md`，專案規則一律寫在本檔。
- `docs/sample-report.md` 由 `python scripts/render-sample-report.py` 依 `docs/sample-report.json` 產生（中文報告、`---`、英文報告），不可手改；報告產生器改了就重產。
- 改到 `pyproject.toml` 的 `[tool.mutmut]` 所列模組或它們的測試時，跑 `scripts/mutation-test.py`（只看改動的函式：`--changed origin/main`）；CI 的突變 workflow 預設關閉（repository variable `VIBEAUDIT_MUTATION=true` 才自動跑，手動 dispatch 一律跑），所以本機跑是唯一的把關；存活的突變要補測試，真的到不了的程式才標 `# pragma: no mutate`。兩份鎖定檔都用 `scripts/hash-lock.py` 重產（第二份加 `--lock requirements.mutation.lock.txt`）。

## 整合測試開關

未設定時，對應的測試會 skip 並寫明原因。

| 變數 | 啟用的測試 |
|---|---|
| `VIBEAUDIT_TEST_DATABASE_URL`、`VIBEAUDIT_TEST_POSTGRES` | PostgreSQL 儲存、lease 與 checkpoint 測試 |
| `VIBEAUDIT_TEST_NODE` | TypeScript Web fixture（需要 Node 24） |
| `VIBEAUDIT_TEST_WORKER_IMAGE`、`VIBEAUDIT_INTEGRATION_IMAGE`、`VIBEAUDIT_FIXTURE_IMAGE`、`VIBEAUDIT_TEST_RUNTIME_CONFIG` | Docker worker、掃描器、工具與 fixture 整合（見 docs/DOCKER_INTEGRATION_TESTING.md） |
| `VIBEAUDIT_JUNIT_XML` | `scripts/verify-linux.sh` 寫出 JUnit 收據 |

---
# AGENTS.md

Vibe Audit 0.2.1: evidence-gated multi-model security testing workbench. Python backend in `backend/vibe_audit`, React console in `frontend/`. Architecture: README "Architecture Overview" and `docs/ARCHITECTURE.md`; API and module contracts: `IMPLEMENTATION.md`.

## Reply language

Reply in Traditional Chinese with Taiwanese usage. Give technical terms in both Chinese and English, for example 單一來源（single source of truth）. Use English only where it is required: code, commands, identifiers, file paths, and messages the repository's conventions keep in English.

## Commands

Run everything from the repository root; catalogs, fixtures and the built UI are not inside the Python package.

```sh
python -m pip install --require-hashes -r requirements.lock.txt   # pinned, hash-checked
PYTHONPATH=backend python -m pytest tests -q -rs                  # -rs: read every skip reason
python scripts/package-release.py --manifest-only                 # after changing any tracked file
python scripts/package-release.py --check                         # CI runs this
python scripts/redact-receipts.py --check                         # receipts in docs/ name no host or account
python -m ruff check backend tests scripts                        # lint: unused names and imports, syntax errors, bugbear (rules in pyproject.toml)
sh scripts/contract-smoke.sh                                      # the console's SSR/API contract smoke against a real loopback backend (CI runs it)
cd frontend && npm ci && npm run typecheck && npm test && npm run check:i18n && npm run check:messages && npm run build   # dist/ is committed; npm test runs the vitest unit and component tests in tests/; check:i18n finds interface Chinese with no English counterpart; check:messages compares how the console and backend read the message table
git add -N frontend/dist && git diff --exit-code -- frontend/dist # CI: dist must match the sources
python -m pip install --require-hashes -r requirements.mutation.lock.txt && python scripts/mutation-test.py   # mutation testing (Linux): every mutant of the gate and parser modules must be caught
```

## Rules

- `source-manifest.sha256` pins every tracked file. Regenerate it with the script, never by hand.
- `.gitattributes` sets `* -text`: keep each file's existing line endings (`scripts/package-release.py` and some others are CRLF). Shell scripts stay LF.
- README.md, docs/ARCHITECTURE.md, IMPLEMENTATION.md, docs/VALIDATION.md and other docs are bilingual (Chinese and English halves). Change both halves together. Chinese is Traditional Chinese with Taiwanese usage.
- tests/test_bilingual_docs.py checks that every document is a Chinese half, `---`, then an English half with matching headings, and that document titles name the pyproject.toml version.
- The console is bilingual: write every visible string as `t('中文','English')` where it is used, and module-level label tables with `labels()` from `frontend/src/i18n.ts`.
- English text the engine writes itself (errors, activity events, gaps, verdicts, demo content) needs Chinese wording in `backend/vibe_audit/messages.py`; `tests/test_error_messages.py` finds what is missing, and the console shows it with `say()`. Model, scanner, target and operator text is never translated.
- Authoritative validation lives in `domain.py`, `contracts.py`, `policy.py` and `docs/run-input.schema.json`; keep docs consistent with them.
- A skipped test is not a pass. Do not record skips as verification in docs/VALIDATION.md.
- Run `python scripts/redact-receipts.py` before adding a JUnit receipt to docs/, then `python scripts/summarize-validation.py`.
- `.claude/`, this file and `CLAUDE.md` are excluded from releases by `scripts/package-release.py`. `CLAUDE.md` holds the single line `@AGENTS.md`; every project rule lives in this file.
- `docs/sample-report.md` is rendered from `docs/sample-report.json` by `python scripts/render-sample-report.py` (Chinese report, `---`, English report). Never edit it by hand; re-render it when the report generator changes.
- After changing a module listed under `[tool.mutmut]` in `pyproject.toml`, or its tests, run `scripts/mutation-test.py` (`--changed origin/main` for the changed functions only); the mutation workflows in CI are off by default (they run on their own only with the repository variable `VIBEAUDIT_MUTATION=true`; a manual dispatch always runs), so the local run is the only gate; a surviving mutant needs a test, and only genuinely unreachable code gets `# pragma: no mutate`. Regenerate either lock file with `scripts/hash-lock.py` (`--lock requirements.mutation.lock.txt` for the second).

## Integration test switches

Unset means the matching tests skip with a stated reason.

| Variable | Enables |
|---|---|
| `VIBEAUDIT_TEST_DATABASE_URL`, `VIBEAUDIT_TEST_POSTGRES` | PostgreSQL store, lease and checkpoint tests |
| `VIBEAUDIT_TEST_NODE` | TypeScript Web fixture (needs Node 24) |
| `VIBEAUDIT_TEST_WORKER_IMAGE`, `VIBEAUDIT_INTEGRATION_IMAGE`, `VIBEAUDIT_FIXTURE_IMAGE`, `VIBEAUDIT_TEST_RUNTIME_CONFIG` | Docker worker, scanner, tool and fixture integrations (see docs/DOCKER_INTEGRATION_TESTING.md) |
| `VIBEAUDIT_JUNIT_XML` | `scripts/verify-linux.sh` writes a JUnit receipt |
