# Vibe Audit 領域詞彙

本詞彙表記錄以證據把關的多模型資安評估中，已確認的模型呼叫概念。

## 模型回答與計量

**模型回答（Model answer）**：
一次審查問題的有效答案，以及實際產生該答案的模型身分；使用備援時，原定 reviewer 與實際回答者可不同。

**模型預留額（Model reservation）**：
在模型嘗試前，從評估共用 token 預算保留的保守額度。已送出而無法確認用量時，不能視為未消耗額度。

**備援回答（Fallback answer）**：
原定模型拒答或輸出被截斷後，由操作者明確指定的備援模型提供的有效答案；嘗試詢問備援但沒有答案，不構成備援回答。

---
# Vibe Audit domain glossary

This glossary records resolved model-call concepts in evidence-gated multi-model security assessments.

## Model answers and accounting

**Model answer**:
A valid answer to a review question together with the identity of the model that produced it. With fallback, the assigned reviewer and actual author can differ.

**Model reservation**:
A conservative allowance held against an assessment's shared token budget before a model attempt. Dispatched attempts with unknown usage cannot be treated as unspent allowance.

**Fallback answer**:
A valid answer from an operator-designated fallback after the original model refuses or is truncated. Asking a fallback without receiving an answer does not constitute a fallback answer.
