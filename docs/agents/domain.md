# 領域文件

本專案採 single-context：領域詞彙位於根目錄 GLOSSARY.md，
架構決策位於 docs/adr/。

## 閱讀與維護規則

- 探索程式前，先讀 GLOSSARY.md 與涉及該範圍的 ADR。
- 文件不存在時直接繼續；由 domain-modeling 在詞彙或決策
  確立時建立，無須預先產生空白文件。
- 輸出領域概念時，沿用 glossary 定義的名稱。
- 遇到未定義概念時，先確認是否符合專案語言，再交由
  domain-modeling 討論與記錄。
- 建議若牴觸 ADR，明確指出 ADR 編號與值得重新討論的理由。

---
# Domain docs

This repository uses single-context documentation:
GLOSSARY.md at the root and architecture decisions in docs/adr/.

## Reading and maintenance rules

- Before exploring code, read GLOSSARY.md and relevant ADRs.
- Proceed silently when they are absent. Let domain-modeling create
  them when terms or decisions are resolved.
- Use the glossary's names for domain concepts.
- For undefined concepts, check the project's language before
  discussing and recording them through domain-modeling.
- Explicitly identify any conflicting ADR and explain why revisiting
  it is justified.
