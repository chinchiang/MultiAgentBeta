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
