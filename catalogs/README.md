# 固定版本的標準目錄

應用程式只從此目錄載入資料，不在評估期間連外更新。`manifest.json` 保存每個集合與原始檔的 SHA-256；`source-lock.json` 保存抓取時間、官方 URL 與可用的精確 Git commit。

採用 ASVS 5.0.0 正式 release tag、WSTG 4.2 tag、LLM Top 10 2026 canonical final sources，以及 Agentic 2026。原始資料與衍生 catalog 的授權為 **CC-BY-SA-4.0**，歸屬 OWASP Foundation 與各專案貢獻者；這些內容的授權獨立於工具程式碼的 Apache-2.0。授權原文保存於 `sources/asvs-LICENSE.md` 與 `sources/wstg-LICENSE.txt`，LLM repository README 也明確載明同一授權。依 CC-BY-SA 使用、散布或改編時須保留署名與相同授權。

本地 JSON 的改編包括：正規化成一致欄位、增加版本與來源欄位、替 ASVS 加入名稱空間、替 Agentic 加入版本後綴。ID 與標題由來源擷取；不由模型生成。未自行翻譯官方條文。

| 集合 | 應用程式 ID | 官方原始 ID | 核對 |
|---|---|---|---|
| ASVS 5.0.0 | `ASVS-v5.0.0-8.2.2` | `v5.0.0-8.2.2` | release-tag JSON 與 CSV 全部 requirement ID 集合相等 |
| WSTG 4.2 | `WSTG-v42-ATHZ-04` | `WSTG-ATHZ-04` | 同 tag JSON 與 Markdown checklist 全部 scenario ID 集合相等 |
| LLM 2026 | `LLM03:2026` | 相同 | canonical final 十篇標題與官方 README 十項清單逐一一致 |
| Agentic 2026 | `ASI01:2026` | `ASI01` | 官方 ASI mapping 與正式發布公告十項逐一核對 |

`v5.0.0-*` 是 ASVS 明確相容別名，解析後回傳 `ASVS-v5.0.0-*`。未知版次、未加版本的 WSTG／ASI、虛構章節會被拒絕。LLM 2025 與 2026 分類排序不同；不能把舊 ID 只更換年份。

## 更新及驗證

從專案根目錄執行 `python scripts/refresh-catalog.py` 可在完全離線狀態檢查原始內容摘要、重新擷取與交叉比對；它只在記憶體中重建並回報差異，不寫入任何檔案（有差異時 exit 1）。審核後以 `--write` 改寫 canonical 檔案與 manifest；內容沒變時輸出逐位元組相同，`generated_at` 也不變。輸出固定使用 CRLF，Windows 與 Linux 產生相同雜湊。`--fetch` 才會下載腳本內固定版本的官方來源；不自動追蹤 main。若需要新版本，先審核並修改明確 commit，再對變更做版本審查。

Hash 只能檢測相對於可信 manifest 的變動，不是 OWASP 簽章；整個目錄需和應用程式發行物一起可信交付。`VIBEAUDIT_CATALOG_ROOT` 可讓從原始碼目錄啟動的服務改用另一份經審核的 catalog 目錄（例如測試）；本工具只從原始碼目錄啟動，複製出去的 wheel 會拒絕啟動，這個變數不改變這一點。

## 已記錄的來源差異

- 官方 LLM 2026 landing page 的日期為 8 月 3 日，repository README 為 8 月 4 日；內容明確指向同一 2026 版。此差異不影響本地 ID 核對。
- 舊 `/llm-top-10/` 網頁仍顯示 2025，未用它生成 2026 ID。
- 官方 LLM／Agentic PDF 下載在此環境導向 no-access HTML，未取得 PDF；不宣稱 PDF 與 Markdown 相等，也不把 HTML 保存為 PDF。來源內容以公開官方 canonical repository 與官方公告互證。無登入或存取限制繞過。
- Agentic repository 仍有歷史初稿，不能以 `ASI01` 的舊草稿名稱取代正式發布名稱。此目錄使用官方發布公告與 final LLM2026 的 ASI mapping。
- ASI02、ASI05 的發布公告使用簡稱，JSON 保留正式 mapping 的完整名稱。
- WSTG 4.2 官方 checklist 有 98 列、97 個不同 ID；Buffer Overflow 與 Format String Injection 共用 `WSTG-INPV-13`。本地以同一真實 ID 合併，保留兩個子項名稱與目的，不自創替代識別碼。最終目錄共有 345 + 97 + 10 + 10 = 462 個不同 ID。

這是標準 ID 的完整目錄，不是所有標準要求都已實作測試，也不代表 OWASP 認證。
