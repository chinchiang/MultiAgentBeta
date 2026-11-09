# 程式碼審查規範 — 0.2.1

審查（review）一份 diff 時讀這份規範，實作時不必讀。這裡只收工具抓不到的判斷題。lint、型別、測試、manifest、雙語文件結構與模組對照表，已經由 `ruff`、`mypy`、pytest 與 CI 檢查，不在這裡重複。每一項都是判斷題，回報時要寫明理由，並引用 diff 裡的那一段。

## 文件與程式一致

- 改變模組的職責、介面或續跑規則時，對照三份文件的描述，確認仍然正確：`IMPLEMENTATION.md` 的模組契約、`docs/ARCHITECTURE.md` 的模組對照表、`GLOSSARY.md` 的用語。測試只檢查模組有列進對照表，不檢查描述對不對。
- 刪掉一條路（參數、函式、快取）時，說明、註解、docstring 與 README 目錄樹裡提到它的字句也一起拿掉。
- 階段改用另一個模組時，README「系統架構與流程」的各階段模組表要跟著改。
- 改變一個元件在哪裡執行、對誰生效（例如 hook 從只在雲端改成本機也執行）時，README 目錄樹與文件裡描述它的那一行要跟著改。

## 行為變化

- 重構宣稱行為不變時，既有測試的斷言不改。只換假造的層次不算改斷言，例如把 monkeypatch 改成注入 `FakePort`。斷言改了，PR 內文就要寫明是哪一項刻意的行為變化。
- 新增的測試如果在舊程式上本來就會通過，PR 內文要標成特性測試（characterization test），不寫成紅燈轉綠。

## 續跑與保留

- 階段的輸出欄位（例如 `commander_plan`、`report_order`）跟保留的答案一起失效：重問之前先清掉舊的輸出，失敗時不留下讓下次續跑誤判的狀態。
- `StageAnswers.answer` 的區塊裡，只放依賴這份答案的檢查。

## 測試

- 測試透過公開介面驗證行為。預期值來自獨立的來源，例如字面值、規格或算好的例子，不照著程式的算法重算一次。

---

# Code review standards — 0.2.1

Read these when reviewing a diff; implementation does not need them. They hold only the judgement calls no tool catches. Lint, types, tests, the manifest, the bilingual document structure and the module map are checked by `ruff`, `mypy`, pytest and CI and are not repeated here. Each item is a judgement call: report it with the reason and quote the hunk.

## Docs match the code

- When a change alters a module's responsibility, interface or resume rules, check that three descriptions still hold: the module contract in `IMPLEMENTATION.md`, the module map in `docs/ARCHITECTURE.md`, and the terms in `GLOSSARY.md`. The tests only check that a module is listed in the module map, not that its description is right.
- When a path goes (a parameter, a function, a cache), the words in descriptions, comments, docstrings and the README tree that name it go too.
- When a stage moves onto another module, the per-stage module table in the README's "Architecture Overview" changes with it.
- When a change alters where a component runs or whom it applies to (a hook that ran only in the cloud now runs locally too, say), the line in the README tree and the docs that describes it changes with it.

## Behaviour changes

- A refactor that claims unchanged behaviour leaves existing test assertions as they are. Changing only the layer that is faked, such as a monkeypatch replaced by an injected `FakePort`, is not changing an assertion. When an assertion does change, the PR body names the deliberate behaviour change it belongs to.
- A new test that already passes on the old code is labelled a characterization test in the PR body, not written up as going from red to green.

## Resume and keeping

- A stage's output fields (such as `commander_plan` and `report_order`) stop standing together with the answer kept for them: clear the old output before asking again, so a failure leaves no state a later resume would misread.
- The block of `StageAnswers.answer` holds only the checks that depend on that answer.

## Tests

- Tests verify behaviour through the public interface. Expected values come from an independent source, such as a literal, the spec or a worked example, not from recomputing them the way the code does.
