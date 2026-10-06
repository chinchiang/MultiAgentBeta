# VibeSec G2／G3 advisory 分流紀錄

本專案由 chinchiang/MultiAgentDelta 的 VibeSec 閘門以 `--target` 掃描。G2（gitleaks 全 git 歷史）與 G3（semgrep、checkov、trivy）目前各有 8 筆與 24 筆 advisory。advisory 不阻擋，但每次重跑都會再出現，所以這裡逐筆記錄判斷，之後重跑只需比對有沒有新增。

- 最後核對：2026-10-06，main 0fe49c1 之後的 commit。從 cabb124 起，每個修正 commit 都重跑 G2／G3 並逐筆比對，發現集合沒有變；2026-10-06 加入 expat 預掃後，G3 多了它自己的 import 這一筆。
- 這份紀錄由 harness（模型）整理，判斷依據都是可核對的程式位置。它不是 VibeSec 的人工裁決（`rulings/`），也沒有修改任何阻擋政策。
- 祕密一律只留遮罩。

## G2：8 筆，皆非有效祕密（github-pat 一筆依權杖格式的校驗碼判定）

| 規則 | 位置（首次出現的 commit） | 判斷 |
|---|---|---|
| `jwt` | `catalogs/sources/wstg-project.html:46`、`asvs-project.html:56`（c7ae273） | OWASP 公開頁面存檔裡的圖片網址參數 `?token=eyJ…`。解碼後是 `scope: download`，`exp − iat = 600` 秒，早已過期 |
| `jwt` | `tests/test_providers.py:363`（5a59458） | redaction 測試的合成 JWT：payload 是 `{"sub":"synthetic"}`，簽章段解碼後是 `synthetic-signature` |
| `generic-api-key` | `backend/vibe_audit/providers.py:32-33`（c7ae273） | 公開 tiktoken 檔案的 SHA-256 完整性釘選，不是金鑰 |
| `generic-api-key` | `tests/test_engine.py:574`（c571cc8，只在歷史中） | 本機 TestClient 用的測試啟動權杖。這個值是 2026-10-06 修正時加入的，只在測試中使用，從未用於任何部署；之後已改為每次執行時以 `secrets.token_urlsafe(32)` 產生 |
| `github-pat` | `tests/test_real_scanners.py:25、40`（c7ae273，只在歷史中） | 掃描器測試刻意植入的 canary，原碼註明為合成、無效的權杖。GitHub 公開的權杖格式中，最後 6 碼是前 30 碼的 CRC32（base62）；離線核對後，兩種字母表順序都不符，所以它在結構上就不是有效權杖。現在改為每次執行時隨機產生，原始碼中已沒有擬真字串；歷史中那筆仍會被 gitleaks 列出 |

## G3：24 筆，皆為誤判或已有對應控制

| 規則 | 位置 | 判斷 |
|---|---|---|
| `CKV_DOCKER_2`（×5）、`DS-0026`（×4）：沒有 HEALTHCHECK | `deploy/scanners/Dockerfile.gitleaks`、`Dockerfile.osv`、`deploy/worker/Dockerfile`、`Dockerfile.tools`、`Dockerfile.tools.locked` | 全是一次性工作容器，以 `--network none` 跑完即結束，沒有常駐服務可探測。加上 `HEALTHCHECK NONE` 可以消掉這 9 筆（已實測 checkov 與 trivy），但必須重建映像並更新映像釘選與收據，而 tools 映像要在能安裝網路套件的環境才能建置，所以暫不修改 |
| `CKV_DOCKER_7` | `deploy/worker/Dockerfile:4` `FROM ${BASE_IMAGE}` | `BASE_IMAGE` 由操作者提供；LINUX_SETUP.md 規定使用 digest，但程式沒有強制檢查。這正是 t-supply-chain 已接受的殘留 |
| `insecure-hash-algorithm-sha1` | `backend/vibe_audit/providers.py:183` | 已標 `usedforsecurity=False`，用途是對齊 tiktoken 的快取檔名，不能改成 SHA-256 |
| `insecure-file-permissions`（×3） | `staging.py:46`、`store.py:39`、`worker_runtime.py:384` | 設定的是 0o700，只有擁有者可存取 |
| `insecure-file-permissions` | `worker_entry.py:496`（broker socket 0o666） | 容器以不同 UID 連線，所以 socket 本身要可寫。host 上的其他帳號進不來，因為外層工作目錄是 0o700（worker_runtime.py:384）。對容器內的程序，broker token 不是防線（容器可讀 0444 的任務檔，見 t-broker-token）；真正的控制是 supervisor 對每個請求檢查的密封案例範圍、lease 與預算（worker_entry.py:414-415） |
| `use-defused-xml`（×3） | `tool_runners.py:13、14`、`scripts/summarize-validation.py:5` | 第 14 行的 `xml.parsers.expat` 就是這項防護本身。tool_runners 解析容器產出的 XML 前，先以 expat 掃描，任何 DTD 或 entity 宣告都拒絕。expat 的解碼方式與 ElementTree 相同，所以 UTF-16 等非 ASCII 相容編碼也擋得住（`_refuse_xml_declarations`）。summarize-validation 只讀 repo 內自己的 JUnit 收據，以位元組比對拒絕 DOCTYPE／ENTITY（第 12 行）。改用 defusedxml 會新增相依，要另走 G1 |
| `dynamic-urllib-use-detected`（×3） | `scripts/hash-lock.py:24`、`provision-offline-db.py:24`、`refresh-catalog.py:82` | 主機固定為 HTTPS（pypi.org、osv-vulnerabilities.storage.googleapis.com）；refresh-catalog 會先拒絕非 `https://` 的來源 |
| `unknown-value-with-script-tag`（×3） | `frontend/scripts/contract-smoke.mjs:118-119` | 刻意把 `<script>`／`<img onerror>` 丟給 `SafeText`，再斷言輸出已跳脫，這段就是 XSS 防護的測試 |

---

# VibeSec G2/G3 advisory triage record

This project is scanned with `--target` by the VibeSec gates in chinchiang/MultiAgentDelta. G2 (gitleaks over the full git history) and G3 (semgrep, checkov, trivy) currently report 8 and 24 advisories. Advisories do not block, but they come back on every run, so each one is recorded here; later runs only need to check for additions.

- Last checked: 2026-10-06, on the commit after main 0fe49c1. G2/G3 were re-run and compared finding by finding after every fix commit since cabb124, and the finding set has not changed, except that adding the expat pre-scan on 2026-10-06 brought in one G3 entry for its own import.
- This record was compiled by the harness (a model), and every judgement cites a code location that can be checked. It is not a VibeSec human ruling (`rulings/`), and no blocking policy was changed.
- Secrets appear only masked.

## G2: 8 findings, none a valid secret (the github-pat one judged by the token format's checksum)

| Rule | Location (first commit) | Judgement |
|---|---|---|
| `jwt` | `catalogs/sources/wstg-project.html:46`, `asvs-project.html:56` (c7ae273) | An image URL parameter `?token=eyJ…` in an archived public OWASP page. Decoded, it is `scope: download` with `exp − iat = 600` seconds, long expired |
| `jwt` | `tests/test_providers.py:363` (5a59458) | A synthetic JWT for the redaction test: the payload is `{"sub":"synthetic"}` and the signature decodes to `synthetic-signature` |
| `generic-api-key` | `backend/vibe_audit/providers.py:32-33` (c7ae273) | SHA-256 integrity pins of public tiktoken files, not keys |
| `generic-api-key` | `tests/test_engine.py:574` (c571cc8, history only) | A test startup token for the local TestClient. It was added during the 2026-10-06 fixes, used only in tests and never in any deployment; it has since been replaced by `secrets.token_urlsafe(32)` generated on each run |
| `github-pat` | `tests/test_real_scanners.py:25, 40` (c7ae273, history only) | A canary deliberately planted for the scanner test; the original code labelled it a synthetic, invalid token. In GitHub's published token format the last 6 characters are a base62 CRC32 of the first 30; checked offline, it matches under neither alphabet order, so it is not even a structurally valid token. It is now generated randomly on each run, so the source holds no realistic-looking string, though gitleaks still lists the one in history |

## G3: 24 findings, all false positives or covered by an existing control

| Rule | Location | Judgement |
|---|---|---|
| `CKV_DOCKER_2` (×5), `DS-0026` (×4): no HEALTHCHECK | `deploy/scanners/Dockerfile.gitleaks`, `Dockerfile.osv`, `deploy/worker/Dockerfile`, `Dockerfile.tools`, `Dockerfile.tools.locked` | All are one-shot job containers that run with `--network none` and exit; there is no long-running service to probe. Adding `HEALTHCHECK NONE` removes these 9 (verified with checkov and trivy), but the images would have to be rebuilt and their pins and receipts updated, and the tools image can only be built where network package installs work, so this is left unchanged for now |
| `CKV_DOCKER_7` | `deploy/worker/Dockerfile:4` `FROM ${BASE_IMAGE}` | `BASE_IMAGE` is supplied by the operator; LINUX_SETUP.md requires a digest, but nothing in the code enforces it. That is exactly the accepted t-supply-chain residual |
| `insecure-hash-algorithm-sha1` | `backend/vibe_audit/providers.py:183` | Marked `usedforsecurity=False`; it matches tiktoken's cache file names and cannot become SHA-256 |
| `insecure-file-permissions` (×3) | `staging.py:46`, `store.py:39`, `worker_runtime.py:384` | The mode set is 0o700, owner only |
| `insecure-file-permissions` | `worker_entry.py:496` (broker socket 0o666) | The container connects under a different UID, so the socket itself must be writable. Other host accounts cannot reach it because the enclosing work directory is 0o700 (worker_runtime.py:384). For processes inside the container the broker token is not the defense (the container can read the 0444 task file; see t-broker-token); the real controls are the sealed-case scope, lease and budget the supervisor checks on every request (worker_entry.py:414-415) |
| `use-defused-xml` (×3) | `tool_runners.py:13, 14`, `scripts/summarize-validation.py:5` | The `xml.parsers.expat` import on line 14 is this protection itself. Before parsing XML produced by the container, tool_runners scans it with expat and refuses any DTD or entity declaration. expat decodes exactly as ElementTree does, so encodings that are not ASCII-compatible, such as UTF-16, are covered too (`_refuse_xml_declarations`). summarize-validation reads only the repository's own JUnit receipts and refuses DOCTYPE/ENTITY by byte search (line 12). Switching to defusedxml would add a dependency that has to go through G1 |
| `dynamic-urllib-use-detected` (×3) | `scripts/hash-lock.py:24`, `provision-offline-db.py:24`, `refresh-catalog.py:82` | Fixed HTTPS hosts (pypi.org, osv-vulnerabilities.storage.googleapis.com); refresh-catalog first refuses any source that is not `https://` |
| `unknown-value-with-script-tag` (×3) | `frontend/scripts/contract-smoke.mjs:118-119` | Deliberately feeds `<script>`/`<img onerror>` to `SafeText` and asserts the output is escaped: this is the XSS-protection test |
