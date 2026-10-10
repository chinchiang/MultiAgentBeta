# 來源清冊

規劃期間於 2026-09-24 查閱；實作相依套件另行凍結於 requirements.lock.txt/package-lock.json。文件／來源交叉核對並非對實際安全成效的宣稱。未複製任何上游 AGPL 程式碼。

| 決策 | 主要參考資料 | 驗證界線 |
|---|---|---|
| LangGraph 檢查點與副作用 | https://docs.langchain.com/oss/python/langgraph/persistence ; https://docs.langchain.com/oss/python/langgraph/interrupts ; https://github.com/langchain-ai/langgraph | 以已安裝的圖譜與真實 PostgreSQL 進行檢查點／交易測試；詳見 VALIDATION.md |
| 各模型轉接器 | https://docs.litellm.ai/docs/providers/nvidia_nim ; https://github.com/BerriAI/litellm/blob/main/litellm/llms/nvidia_nim/chat/transformation.py | 已以實際 SDK 與合成 HTTP 驗證；未進行真實憑證測試 |
| 威脅建模 | https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html ; https://github.com/OWASP/CheatSheetSeries | 供 schema 設計參考；完整性仍取決於應用程式需求 |
| ASVS/WSTG | https://github.com/OWASP/ASVS ; https://wstg.owasp.org/v4.2/ | 以官方 JSON/CSV 匯入標準目錄並與來源交叉核對；詳見 catalogs/manifest.json；非合規認證 |
| LLM/Agentic 2026 | https://raw.githubusercontent.com/GenAI-Security-Project/GenAI-LLM-Top10/main/2026/README.md ; https://raw.githubusercontent.com/GenAI-Security-Project/GenAI-LLM-Top10/main/CITATION.cff ; https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | 名稱／編號已交叉核對。PDF 出版日期佔位符與日期不一致之處，仍為來源品質上的注意事項。標準目錄的來源、commit 與內容雜湊記錄於 catalogs/manifest.json |
| 多代理效益的界限 | https://arxiv.org/abs/2305.14325 ; https://proceedings.mlr.press/v235/smit24a.html | 一般性任務結果並不能證明程式碼安全性的改善 |
| Semgrep 規則授權 | https://semgrep.dev/legal/rules-license/ ; https://github.com/semgrep/semgrep | 僅使用自訂的本機範例規則；未捆綁受限規則 |
| ZAP | https://www.zaproxy.org/docs/desktop/addons/automation-framework/ ; https://github.com/zaproxy/zap-extensions | 以固定的請求發送器／被動掃描執行器，在隔離的 Docker 中對正／負向本機測試素材執行驗證 |
| Schemathesis/Playwright | https://schemathesis.readthedocs.io/en/latest/guides/extending/ ; https://playwright.dev/docs/api-testing | 不宣稱能自動理解業務授權邏輯 |
| promptfoo | https://www.promptfoo.dev/docs/red-team/troubleshooting/data-handling/ ; https://github.com/promptfoo/promptfoo | 僅限遠端的外掛不會被靜默啟用 |
| PyRIT | https://github.com/microsoft/PyRIT/blob/main/pyrit/executor/workflow/xpia.py ; https://github.com/microsoft/PyRIT/blob/main/pyrit/score/true_false/otel_tool_call_scorer.py | 呼叫本身並非已產生副作用的證據 |
| 分詞器資產 | https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken ; installed tiktoken_ext/openai_public.py | SHA256 223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7；於安裝階段下載，執行階段禁止下載 |

授權參考：LangGraph MIT；LiteLLM 非企業版採 MIT，企業版另有獨立條款；Strix Apache-2.0；Shannon AGPL-3.0（僅供參照）；Gitleaks MIT；OSV-Scanner Apache-2.0。工具映像、模型權重、規則與資料保留其自身授權。根授權條款永不凌駕於前述條款之上。

---
# Source ledger

Accessed 2026-09-24 during planning; implementation dependencies are separately frozen in requirements.lock.txt/package-lock.json. Documentation/source cross-check is not a claim of measured security efficacy. No upstream AGPL code was copied.

| Decision | Primary references | Verification boundary |
|---|---|---|
| LangGraph checkpoints and side effects | https://docs.langchain.com/oss/python/langgraph/persistence ; https://docs.langchain.com/oss/python/langgraph/interrupts ; https://github.com/langchain-ai/langgraph | Installed graph and real PostgreSQL checkpoint/transaction tests; see VALIDATION.md |
| Per-model adapters | https://docs.litellm.ai/docs/providers/nvidia_nim ; https://github.com/BerriAI/litellm/blob/main/litellm/llms/nvidia_nim/chat/transformation.py | Actual SDK + synthetic HTTP verified; no real credential tests |
| Threat modeling | https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html ; https://github.com/OWASP/CheatSheetSeries | Informs schema; completeness still depends on application requirements |
| ASVS/WSTG | https://github.com/OWASP/ASVS ; https://wstg.owasp.org/v4.2/ | Canonical catalog ingestion with official JSON/CSV and source cross-checks; see catalogs/manifest.json; not compliance certification |
| LLM/Agentic 2026 | https://raw.githubusercontent.com/GenAI-Security-Project/GenAI-LLM-Top10/main/2026/README.md ; https://raw.githubusercontent.com/GenAI-Security-Project/GenAI-LLM-Top10/main/CITATION.cff ; https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | Names/IDs cross-checked. PDF publication-date placeholders and date discrepancies remain a source-quality caveat. Canonical catalog sources, commits and content hashes are recorded in catalogs/manifest.json |
| Multi-agent benefit limits | https://arxiv.org/abs/2305.14325 ; https://proceedings.mlr.press/v235/smit24a.html | General task results do not establish code-security improvement |
| Semgrep rules licensing | https://semgrep.dev/legal/rules-license/ ; https://github.com/semgrep/semgrep | Custom local sample rules only; no restricted rules bundled |
| ZAP | https://www.zaproxy.org/docs/desktop/addons/automation-framework/ ; https://github.com/zaproxy/zap-extensions | Fixed requestor/passive runner exercised in isolated Docker against positive/negative local fixtures |
| Schemathesis/Playwright | https://schemathesis.readthedocs.io/en/latest/guides/extending/ ; https://playwright.dev/docs/api-testing | No claim of automatic business-authorization understanding |
| promptfoo | https://www.promptfoo.dev/docs/red-team/troubleshooting/data-handling/ ; https://github.com/promptfoo/promptfoo | Remote-only plugins not silently enabled |
| PyRIT | https://github.com/microsoft/PyRIT/blob/main/pyrit/executor/workflow/xpia.py ; https://github.com/microsoft/PyRIT/blob/main/pyrit/score/true_false/otel_tool_call_scorer.py | Invocation is not committed side-effect evidence |
| Tokenizer asset | https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken ; installed tiktoken_ext/openai_public.py | SHA256 223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7; downloaded at setup, runtime downloads forbidden |

License references: LangGraph MIT; LiteLLM non-enterprise MIT with separate enterprise terms; Strix Apache-2.0; Shannon AGPL-3.0 (reference only); Gitleaks MIT; OSV-Scanner Apache-2.0. Tool images, model weights, rules and data retain their own licenses. Root license never overrides those terms.
