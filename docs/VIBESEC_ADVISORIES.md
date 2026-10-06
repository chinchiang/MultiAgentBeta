# VibeSec G2／G3 advisory 分流紀錄

本專案由 chinchiang/MultiAgentDelta 的 VibeSec 閘門以 `--target` 掃描。G2（gitleaks 全 git 歷史）與 G3（semgrep、checkov、trivy）目前各有 8 筆與 23 筆 advisory。advisory 不阻擋，但每次重跑都會再出現，所以這裡逐筆記錄判斷，之後重跑只需比對有沒有新增。

- 最後核對：2026-10-06，main 0fe49c1 之後的 commit。從 cabb124 起，每個修正 commit 都重跑 G2／G3 並逐筆比對，發現集合沒有變。
- 這份紀錄由 harness（模型）整理，判斷依據都是可核對的程式位置。它不是 VibeSec 的人工裁決（`rulings/`），也沒有修改任何阻擋政策。
- 祕密一律只留遮罩。

## G2：8 筆，皆非有效祕密

| 規則 | 位置（首次出現的 commit） | 判斷 |
|---|---|---|
| `jwt` | `catalogs/sources/wstg-project.html:46`、`asvs-project.html:56`（c7ae273） | OWASP 公開頁面存檔裡的圖片網址參數 `?token=eyJ…`。解碼後是 `scope: download`，`exp − iat = 600` 秒，早已過期 |
| `jwt` | `tests/test_providers.py:363`（5a59458） | redaction 測試的合成 JWT：payload 是 `{"sub":"synthetic"}`，簽章段解碼後是 `synthetic-signature` |
| `generic-api-key` | `backend/vibe_audit/providers.py:32-33`（c7ae273） | 公開 tiktoken 檔案的 SHA-256 完整性釘選，不是金鑰 |
| `generic-api-key` | `tests/test_engine.py:574`（c571cc8，只在歷史中） | 本機 TestClient 用的測試啟動權杖。這個值是 2026-10-06 修正時加入的，只在測試中使用，從未用於任何部署；之後已改為每次執行時以 `secrets.token_urlsafe(32)` 產生 |
| `github-pat` | `tests/test_real_scanners.py:25、40`（c7ae273，只在歷史中） | 掃描器測試刻意植入的 canary，原碼註明為合成、無效的權杖。現在改為每次執行時隨機產生，原始碼中已沒有擬真字串；歷史中那筆仍會被 gitleaks 列出。是否確實無效，只有權杖擁有者能確認 |

## G3：23 筆，皆為誤判或已有對應控制

| 規則 | 位置 | 判斷 |
|---|---|---|
| `CKV_DOCKER_2`（×5）、`DS-0026`（×4）：沒有 HEALTHCHECK | `deploy/scanners/Dockerfile.gitleaks`、`Dockerfile.osv`、`deploy/worker/Dockerfile`、`Dockerfile.tools`、`Dockerfile.tools.locked` | 全是一次性工作容器，以 `--network none` 跑完即結束，沒有常駐服務可探測。加上 `HEALTHCHECK NONE` 可以消掉這 9 筆（已實測 checkov 與 trivy），但必須重建映像並更新映像釘選與收據，而 tools 映像要在能安裝網路套件的環境才能建置，所以暫不修改 |
| `CKV_DOCKER_7` | `deploy/worker/Dockerfile:4` `FROM ${BASE_IMAGE}` | `BASE_IMAGE` 由操作者以 digest 提供（LINUX_SETUP.md），已記為 t-supply-chain 的接受殘留 |
| `insecure-hash-algorithm-sha1` | `backend/vibe_audit/providers.py:183` | 已標 `usedforsecurity=False`，用途是對齊 tiktoken 的快取檔名，不能改成 SHA-256 |
| `insecure-file-permissions`（×3） | `staging.py:46`、`store.py:39`、`worker_runtime.py:384` | 設定的是 0o700，只有擁有者可存取 |
| `insecure-file-permissions` | `worker_entry.py:496`（broker socket 0o666） | socket 位於 0o711 的 `broker/` 目錄、外層是 0o700 的工作目錄。容器以不同 UID 連線，所以 socket 本身要可寫；授權由 supervisor 逐請求檢查 broker token（t-broker-token） |
| `use-defused-xml`（×2） | `tool_runners.py:13`、`scripts/summarize-validation.py:5` | 解析前遇到 `<!DOCTYPE`／`<!ENTITY` 就拒絕（tool_runners.py:239、summarize-validation.py:12）。改用 defusedxml 會新增相依，要另走 G1 |
| `dynamic-urllib-use-detected`（×3） | `scripts/hash-lock.py:24`、`provision-offline-db.py:24`、`refresh-catalog.py:82` | 主機固定為 HTTPS（pypi.org、osv-vulnerabilities.storage.googleapis.com）；refresh-catalog 會先拒絕非 `https://` 的來源 |
| `unknown-value-with-script-tag`（×3） | `frontend/scripts/contract-smoke.mjs:118-119` | 刻意把 `<script>`／`<img onerror>` 丟給 `SafeText`，再斷言輸出已跳脫，這段就是 XSS 防護的測試 |

---

# VibeSec G2/G3 advisory triage record

This project is scanned with `--target` by the VibeSec gates in chinchiang/MultiAgentDelta. G2 (gitleaks over the full git history) and G3 (semgrep, checkov, trivy) currently report 8 and 23 advisories. Advisories do not block, but they come back on every run, so each one is recorded here; later runs only need to check for additions.

- Last checked: 2026-10-06, on the commit after main 0fe49c1. G2/G3 were re-run and compared finding by finding after every fix commit since cabb124, and the finding set has not changed.
- This record was compiled by the harness (a model), and every judgement cites a code location that can be checked. It is not a VibeSec human ruling (`rulings/`), and no blocking policy was changed.
- Secrets appear only masked.

## G2: 8 findings, none a valid secret

| Rule | Location (first commit) | Judgement |
|---|---|---|
| `jwt` | `catalogs/sources/wstg-project.html:46`, `asvs-project.html:56` (c7ae273) | An image URL parameter `?token=eyJ…` in an archived public OWASP page. Decoded, it is `scope: download` with `exp − iat = 600` seconds, long expired |
| `jwt` | `tests/test_providers.py:363` (5a59458) | A synthetic JWT for the redaction test: the payload is `{"sub":"synthetic"}` and the signature decodes to `synthetic-signature` |
| `generic-api-key` | `backend/vibe_audit/providers.py:32-33` (c7ae273) | SHA-256 integrity pins of public tiktoken files, not keys |
| `generic-api-key` | `tests/test_engine.py:574` (c571cc8, history only) | A test startup token for the local TestClient. It was added during the 2026-10-06 fixes, used only in tests and never in any deployment; it has since been replaced by `secrets.token_urlsafe(32)` generated on each run |
| `github-pat` | `tests/test_real_scanners.py:25, 40` (c7ae273, history only) | A canary deliberately planted for the scanner test; the original code labelled it a synthetic, invalid token. It is now generated randomly on each run, so the source holds no realistic-looking string, though gitleaks still lists the one in history. Only the token owner can confirm it is invalid |

## G3: 23 findings, all false positives or covered by an existing control

| Rule | Location | Judgement |
|---|---|---|
| `CKV_DOCKER_2` (×5), `DS-0026` (×4): no HEALTHCHECK | `deploy/scanners/Dockerfile.gitleaks`, `Dockerfile.osv`, `deploy/worker/Dockerfile`, `Dockerfile.tools`, `Dockerfile.tools.locked` | All are one-shot job containers that run with `--network none` and exit; there is no long-running service to probe. Adding `HEALTHCHECK NONE` removes these 9 (verified with checkov and trivy), but the images would have to be rebuilt and their pins and receipts updated, and the tools image can only be built where network package installs work, so this is left unchanged for now |
| `CKV_DOCKER_7` | `deploy/worker/Dockerfile:4` `FROM ${BASE_IMAGE}` | `BASE_IMAGE` is supplied by the operator as a digest (LINUX_SETUP.md); recorded as an accepted t-supply-chain residual |
| `insecure-hash-algorithm-sha1` | `backend/vibe_audit/providers.py:183` | Marked `usedforsecurity=False`; it matches tiktoken's cache file names and cannot become SHA-256 |
| `insecure-file-permissions` (×3) | `staging.py:46`, `store.py:39`, `worker_runtime.py:384` | The mode set is 0o700, owner only |
| `insecure-file-permissions` | `worker_entry.py:496` (broker socket 0o666) | The socket sits in the 0o711 `broker/` directory inside a 0o700 work directory. The container connects under a different UID, so the socket itself must be writable; the supervisor checks the broker token on every request (t-broker-token) |
| `use-defused-xml` (×2) | `tool_runners.py:13`, `scripts/summarize-validation.py:5` | Input containing `<!DOCTYPE`/`<!ENTITY` is refused before parsing (tool_runners.py:239, summarize-validation.py:12). Switching to defusedxml would add a dependency that has to go through G1 |
| `dynamic-urllib-use-detected` (×3) | `scripts/hash-lock.py:24`, `provision-offline-db.py:24`, `refresh-catalog.py:82` | Fixed HTTPS hosts (pypi.org, osv-vulnerabilities.storage.googleapis.com); refresh-catalog first refuses any source that is not `https://` |
| `unknown-value-with-script-tag` (×3) | `frontend/scripts/contract-smoke.mjs:118-119` | Deliberately feeds `<script>`/`<img onerror>` to `SafeText` and asserts the output is escaped: this is the XSS-protection test |
