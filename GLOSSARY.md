# Vibe Audit 用語 — 0.2.1

這份用語表收錄本專案特有的概念，讓程式、文件與討論用同一套詞。一般的程式設計概念不收；用語碰到時再加。

## 模型回答

**模型回答（model answer）**：
某個 Agent 對一個問題得到的一份已驗證輸出，連同它的全部代價：送出前預扣的保留額度、計量、一次有界的重試、代答與恢復時的重用。一次模型回答可能包含不只一次模型呼叫。
_避免_：模型呼叫、generation

**保留額度（reservation）**：
送出一次模型呼叫前，從 run 的 token 預算預扣的上限。回答結束時結清：計入實際用量後釋放；取消時整筆算為已用；用量不明時保留下來，之後的付費呼叫一律停止。它不是 run 的預算本身，也不是 lease 的保留帳本。
_避免_：預扣、hold

**代答（fallback answer）**：
主要 Agent 拒答或輸出被截斷時，由操作者設定的備援 Agent 回答同一個問題。這份回答仍放在原 Agent 的位置，並標明實際作答的備援 Agent。它不是重試：重試是同一個 Agent 再問一次。
_避免_：備援呼叫、替代回答

---

# Vibe Audit glossary — 0.2.1

This glossary holds the concepts specific to this project, so the code, the documents and discussion use the same words. General programming concepts stay out; terms are added as they come up.

## Model answers

**Model answer**:
One validated output an Agent obtains for one question, with everything it cost: the reservation held before sending, the metering, one bounded retry, a fallback answer and reuse on resume. One model answer can take more than one model call.
_Avoid_: model call, generation

**Reservation**:
The upper bound held against a run's token budget before one model call is sent. It settles when the answer ends: released once the actual usage is counted; charged in full as used on cancellation; kept when usage is unknown, which stops every later paid call. It is neither the run's budget itself nor the lease's reservation ledger.
_Avoid_: hold, pre-charge

**Fallback answer**:
The answer the operator's fallback Agent gives to the same question when the primary Agent refuses or is truncated. It stays in the primary Agent's place and names the fallback Agent that actually answered. It is not a retry: a retry asks the same Agent again.
_Avoid_: backup call, substitute answer
