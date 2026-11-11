# Vibe Audit 用語 — 0.2.1

這份用語表收錄本專案特有的概念，讓程式、文件與討論用同一套詞。一般的程式設計概念不收；用語碰到時再加。

## 模型回答

**模型回答（model answer）**：
某個 Agent 對一個問題得到的一份已驗證輸出，連同它的全部代價：送出前預扣的保留額度、計量、一次有界的重試與代答。一次模型回答可能包含不只一次模型呼叫。續跑時要不要沿用，不歸模型回答管，見階段答案：模型回答管付費與驗證，階段答案管角色由誰回答、答案留不留。
_避免_：模型呼叫、generation

**階段答案（stage answer）**：
某個階段為一個角色取得的模型回答，通過這個階段的檢查之後才保留，續跑時問同一個問題就沿用、不再付費，並重跑檢查。沒通過檢查就不保留，沿用的答案沒通過也一樣移除，下次續跑重問；取消不算沒通過。審查員的回答不保留，續跑以已封存的審查為準。
_避免_：stage output、cached answer

**保留額度（reservation）**：
送出一次模型呼叫前，從 run 的 token 預算預扣的上限。回答結束時結清：計入實際用量後釋放；取消時整筆算為已用；用量不明時保留下來，之後的付費呼叫一律停止。它不是 run 的預算本身，也不是 lease 的保留帳本。
_避免_：預扣、hold

**代答（fallback answer）**：
主要 Agent 拒答或輸出被截斷時，由操作者設定的備援 Agent 回答同一個問題。這份回答仍放在原 Agent 的位置，並標明實際作答的備援 Agent。備援跟著實際作答的 Agent 走：commander 代替別的角色作答時（例如沒有專職 challenger），由列了 commander 的備援代答。它不是重試：重試是同一個 Agent 再問一次。
_避免_：備援呼叫、替代回答

## 送往目標的請求

**請求規則（request rule）**：
決定一個送往目標的請求能長什麼樣、能不能送出的規則：方法與路徑、header、身分、本文、會不會改變狀態，各自依這一步的來源而定。
_避免_：scope（已指執行範圍）、政策（policy 另指各階段的閘門）

**請求計畫（request plan）**：
案例封存時一起寫進去的逐步請求清單，涵蓋案例本身、它的正向控制與引擎在前後加的 fixture 生命週期。它跟案例一起由雜湊與操作者的核准涵蓋，封存之後送出的每個請求都必須是其中一步。
_避免_：steps（operator 案例的欄位名）、allowed_requests（舊案例的生命週期欄位）

**來源（source）**：
請求計畫裡一步請求是誰寫的：模型、操作者，或引擎。只有列在操作者自己案例清單、而且不是模型寫的案例才算操作者的，其餘都是引擎的；模型寫的步驟受最嚴的請求規則約束。
_避免_：designed_by（案例的欄位，不等於每一步的來源）、作者、provenance（另指證據的來源證明）

**執行範圍（run scope）**：
操作者為一次 run 允許的方法與確切路徑清單。它只是外框：每一步請求都必須在裡面，哪一步能送、以什麼身分送，由請求計畫決定。
_避免_：allowlist、白名單

---

# Vibe Audit glossary — 0.2.1

This glossary holds the concepts specific to this project, so the code, the documents and discussion use the same words. General programming concepts stay out; terms are added as they come up.

## Model answers

**Model answer**:
One validated output an Agent obtains for one question, with everything it cost: the reservation held before sending, the metering, one bounded retry and a fallback answer. One model answer can take more than one model call. Whether a resumed stage reuses it is not the model answer's concern but the stage answer's: the model answer pays for and validates, the stage answer decides who answers a role and whether the answer is kept.
_Avoid_: model call, generation

**Stage answer**:
The model answer a stage obtains for one role, kept only once it passes that stage's checks and reused, unpaid and checked again, when a resumed stage asks the same question. An answer that fails its checks is not kept, and a reused one that fails is removed too, so the next resume asks again; a cancellation is no failure. Reviewers' answers are never kept: a resume goes by the sealed reviews.
_Avoid_: stage output, cached answer

**Reservation**:
The upper bound held against a run's token budget before one model call is sent. It settles when the answer ends: released once the actual usage is counted; charged in full as used on cancellation; kept when usage is unknown, which stops every later paid call. It is neither the run's budget itself nor the lease's reservation ledger.
_Avoid_: hold, pre-charge

**Fallback answer**:
The answer the operator's fallback Agent gives to the same question when the primary Agent refuses or is truncated. It stays in the primary Agent's place and names the fallback Agent that actually answered. The fallback follows the Agent that actually answers: when the commander answers in another role's place (with no dedicated challenger, say), the fallback that lists the commander answers. It is not a retry: a retry asks the same Agent again.
_Avoid_: backup call, substitute answer

## Requests to the target

**Request rule**:
A rule deciding what a request to the target may look like and whether it may be sent: its method and path, headers, identity, body and whether it changes state, each judged by the source of the step.
_Avoid_: scope (that is the run scope), policy (the stages' gates)

**Request plan**:
The step-by-step list of requests sealed into a case: its own request, its positive controls and the fixture lifecycle the engine adds around them. The case hash and the operator's approval cover it with the case, and after sealing every request sent must be one of its steps.
_Avoid_: steps (an operator case's field), allowed_requests (an old case's lifecycle field)

**Source**:
Who wrote one step of a request plan: the model, the operator or the engine. Only a case on the operator's own case list that the model did not write is the operator's, every other is the engine's; a step the model wrote is held to the strictest request rules.
_Avoid_: designed_by (a case's field, not each step's source), author, provenance (the evidence's proof of origin)

**Run scope**:
The methods and exact paths the operator allows for one run. It is only the outer bound: every request step must be inside it, and which step may be sent, as which identity, the request plan decides.
_Avoid_: allowlist, whitelist
