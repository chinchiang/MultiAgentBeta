"""Traditional Chinese (Taiwan) wording for the fixed English messages the API and runs report.

`detail` and `error` stay English, the stable text callers and tests match; `zh()` gives the console the same
message in Chinese. A message from elsewhere (an adapter, a runtime probe) has no entry and stays English.
"""
import re

ZH = {
    # api.py
    "Local session required": "需要本機 session",
    "Invalid runtime profile ID": "執行環境設定檔 ID 無效",
    "Approve with the receipt of the cases you reviewed": "請以你核對過的案例收據核准",
    "Evidence not found in this run": "此執行中找不到該證據",
    "Choose lang en or zh-Hant": "lang 請選 en 或 zh-Hant",
    "Choose json, markdown or sarif": "請選 json、markdown 或 sarif",
    "Source directory is outside configured VIBEAUDIT_SOURCE_ROOTS": "原始碼目錄不在設定的 VIBEAUDIT_SOURCE_ROOTS 之內",
    "Evidence integrity check failed": "證據完整性檢查失敗",
    "A valid profile and explicit probe budget are required": "需要有效的設定檔與明確的探測預算",
    "Probe call budget exhausted": "探測呼叫預算已用完",
    "Report blocked: evidence integrity failure": "報告已封鎖：證據完整性檢查失敗",
    "Run or artifact not found": "找不到該執行或產物",
    "Untrusted Host": "Host 不受信任",
    "Untrusted Origin": "Origin 不受信任",
    "Cross-site access denied": "拒絕跨站存取",
    "Invalid Content-Length": "Content-Length 無效",
    "Request body too large": "請求本文太大",
    "CSRF token required": "需要 CSRF token",
    "Startup token required: open the URL printed when the local service started": "需要啟動權杖：請開啟本機服務啟動時印出的網址",
    "Not Found": "找不到",
    "Method Not Allowed": "不允許此方法",
    # policy.py
    "Run scope or model configuration changed; create a new run": "執行範圍或模型設定已變更；請建立新的執行",
    "Three independent reviewers are required": "需要三位獨立的 reviewer",
    "Incomplete review or source mismatch": "審查不完整或原始碼不一致",
    "Model family diversity incomplete": "模型家族的多樣性不足",
    "Synthetic reviews are not live evidence": "合成審查不能當作實際證據",
    "Missing or stale threat model": "威脅模型缺少或已過時",
    "Threat model requires assets, dataflows and threats": "威脅模型需要資產、資料流與威脅",
    "Threat model hash mismatch": "威脅模型雜湊不符",
    "Threat model requires unique security requirement objects": "威脅模型的安全需求物件不可重複",
    "Execution is cancelled or outside black-box stage": "執行已取消或不在黑箱階段",
    "Missing or expired execution capability": "執行 capability 缺少或已過期",
    "Execution capability no longer matches approved artifacts": "執行 capability 與已核准的產物不再一致",
    "Unapproved case": "案例未經核准",
    "Model-designed cases need the operator's approval of this sealed case set": "模型設計的案例需要操作者核准這組封存案例",
    "Request budget exhausted": "請求預算已用完",
    "Run time budget exhausted": "執行時間預算已用完",
    "Catalog version differs from the run's frozen reference data": "標準目錄版本與此執行凍結的參考資料不同",
    "Unrecognized, unversioned or unverifiable standard reference": "無法辨識、未標版本或無法驗證的標準參照",
    "Security requirement lacks statement or provenance": "安全需求缺少敘述或來源",
    "Dataflow has invalid endpoints or missing trust boundary": "資料流的端點無效或缺少信任邊界",
    "Incomplete or duplicate threat": "威脅不完整或重複",
    "Threat-to-requirement traceability is broken": "威脅與需求之間的追溯中斷",
    "Threat references unknown asset": "威脅參照了不存在的資產",
    "Threat testability missing": "威脅缺少可測試性",
    "Untestable threat needs a reason": "無法測試的威脅需要說明原因",
    "Security requirement references an unknown threat": "安全需求參照了不存在的威脅",
    "Operator security requirement has not been mapped to a threat": "操作者的安全需求尚未對應到威脅",
    "Missing or duplicate case ID": "案例 ID 缺少或重複",
    "Case threat traceability is broken": "案例與威脅之間的追溯中斷",
    "Case security requirement mismatch": "案例的安全需求不符",
    "Case is stale or has been modified": "案例已過時或遭修改",
    "Case needs an executable oracle and observation requirements": "案例需要可執行的 oracle 與觀測要求",
    "Content oracle requires explicit forbidden values": "內容 oracle 需要明確的禁止值",
    "State-changing test requires an explicit cleanup plan": "會改變狀態的測試需要明確的清理計畫",
    "Unavailable adapter": "adapter 無法使用",
    "Observation mode is required": "需要指定觀測模式",
    "Invalid repetition count": "重複次數無效",
    "Case headers cannot carry credentials, relay controls or method/path overrides; a model-designed header must be one the operator listed in allowed_requests[].model_headers for that method and path":
        "案例 header 不得攜帶憑證、relay 控制或覆寫 method/path；模型設計的 header 必須是操作者在 allowed_requests[].model_headers 為該 method 與 path 列出的值",
    "Request method and exact path were not authorized in run scope": "請求的 method 與確切路徑不在執行範圍的授權內",
    "Request is not a step in the sealed test case": "請求不是封存測試案例中的步驟",
    "Identity is outside the sealed case scope": "身分不在封存案例的範圍內",
    "A model-designed case can use only test identities the operator marked as model-selectable": "模型設計的案例只能使用操作者標為 model-selectable 的測試身分",
    "Case or fixture request exceeds the declared method/path scope": "案例或 fixture 請求超出宣告的 method/path 範圍",
    "Trusted fixture configuration changed after case sealing": "受信任的 fixture 設定在案例封存後被變更",
    # service.py
    "Run is already executing": "執行已在進行中",
    "Use resume for an interrupted run or create a new run": "中斷的執行請用恢復，或建立新的執行",
    "Run cannot be resumed in its current state": "執行目前的狀態無法恢復",
    "outcome_unknown: a request's effect on the target is unknown; reset the environment and create a new run": "outcome_unknown：某個請求對目標的影響不明；請重設環境並建立新的執行",
    "Previous provider usage is unknown; this run cannot make further calls": "先前的模型用量不明；此執行不能再呼叫模型",
    "The target's deployment identity changed during this run; test it in a new run": "目標的部署識別在此執行期間變更；請在新的執行中測試",
    "Run is still executing": "執行仍在進行中",
    "Only a run waiting for case approval can be approved": "只有等待核准案例的執行可以核准",
    "The approval does not match the sealed cases; reload the run and review them again": "核准內容與封存的案例不符；請重新載入執行並再次核對",
    "Run is still executing; wait for bounded workers to return": "執行仍在進行中；請等有時限的 worker 回來",
    "Only a run waiting for worker cleanup can be reconciled": "只有等待 worker 清理的執行可以確認清理",
    "Time budget exhausted; remaining work is incomplete": "時間預算已用完；剩下的工作未完成",
    "Runtime configuration changed; create a new run": "執行環境設定已變更；請建立新的執行",
    "Scanner snapshot integrity mismatch": "掃描器快照的完整性不符",
    "Scanner versions, rules or offline data changed after preflight": "掃描器版本、規則或離線資料在預檢後被變更",
    "Finding references evidence outside this run": "發現參照了此執行以外的證據",
    "Finish or stop the original assessment before creating a retest": "請先完成或停止原本的評估，再建立複測",
    "Retest references a finding outside the parent run": "複測參照了上層執行以外的發現",
    "Live runs require VIBEAUDIT_DATABASE_URL (PostgreSQL); SQLite is demo-only": "實測執行需要 VIBEAUDIT_DATABASE_URL（PostgreSQL）；SQLite 只供示範",
    "Isolated runtime unavailable": "隔離執行環境無法使用",
    "The configured worker runtime is the unisolated test backend; live runs need the Docker runtime": "設定的 worker 執行環境是未隔離的測試後端；實測執行需要 Docker 執行環境",
    "No supported source files available": "沒有可支援的原始碼檔案",
    "Source changed after the run was frozen; create a new run": "原始碼在執行凍結後被變更；請建立新的執行",
    "Reviewer returned an invalid review contract": "reviewer 回傳的審查契約無效",
    "Challenger references an unknown finding": "challenger 參照了不存在的發現",
    "Reporter must preserve every existing finding exactly once": "reporter 必須把每個既有發現恰好保留一次",
    "Provider usage is unknown; further model calls stopped": "模型用量不明；已停止後續的模型呼叫",
    "Model call budget exhausted": "模型呼叫預算已用完",
    "Insufficient token budget for bounded model request": "token 預算不足以發出有上限的模型請求",
    "Required model capability probe failed": "必要的模型能力探測失敗",
    "Commander proposal does not preserve three independent reviews": "指揮者的提案沒有保留三份獨立審查",
    "Reviewer finding schema invalid": "reviewer 的發現格式無效",
    "Fixture profile is outside the operator's declared run configuration": "fixture 設定檔不在操作者宣告的執行設定之內",
    "Worker cleanup is unconfirmed; all subsequent cases are stopped": "worker 清理未確認；後續所有案例都已停止",
    "An operation outcome is unknown; reconcile/reset the environment before a new run": "某項操作的結果不明；請先確認或重設環境，再建立新的執行",
    "The target no longer reports the declared deployment identity; test the new deployment in a new run": "目標不再回報宣告的部署識別；請在新的執行中測試新的部署",
    "Controller restarted after a request was sent; reset the target and continue in a new run": "controller 在請求送出後重新啟動；請重設目標並在新的執行中繼續",
    "Controller restarted; resume re-checks every gate against the stored run": "controller 已重新啟動；恢復時會依已儲存的執行重新檢查每道閘門",
    # workspace_api.py
    "Project ID mismatch": "專案 ID 不符",
    "Agent ID mismatch": "代理 ID 不符",
    "Cannot change a finding while its assessment is running": "評估進行中，不能變更它的發現",
    "Finding not found": "找不到該發現",
    "An observed violation stands; verify the fix in a linked retest run": "已觀測到的違規仍然成立；請在連結的複測執行中驗證修復",
    "Counterevidence must belong to this run": "反證必須屬於此執行",
    "A finding's own evidence cannot be cited against it": "不能用發現自身的證據反駁它",
    "Counterevidence must be a black-box execution record": "反證必須是黑箱執行紀錄",
    "The finding's own threat links decide which executions can be cited": "可引用哪些執行，由發現本身連結的威脅決定",
    "Name the threats from this run's threat model that the counterevidence tests": "請列出反證所測試的、此執行威脅模型中的威脅",
    "Counterevidence must come from a case that tests the finding's threats": "反證必須來自測試該發現威脅的案例",
    "Refuting a finding needs an execution in which the security property held": "駁回發現需要一次安全性質成立的執行",
    "A case testing these threats observed a violation in this run; the finding cannot be refuted": "測試這些威脅的案例在此執行中觀測到違規；不能駁回這個發現",
    "Source directory is outside configured source roots": "原始碼目錄不在設定的來源根目錄之內",
}

# Messages that carry run-specific values. Each pattern matches the whole English text; the groups are copied
# into the Chinese wording unchanged (they are IDs, names, sizes or another message).
PATTERNS = [
    (r"Automated threats without cases: (.+)", "自動化威脅沒有對應的案例：{0}"),
    (r"(.+) input exceeds the (\d+) KiB model payload limit even with only the cited files; narrow the source scope or the findings",
     "{0} 的輸入即使只保留引用的檔案，仍超過 {1} KiB 的模型 payload 上限；請縮小原始碼範圍或發現"),
    (r"The threat model omits threat IDs that provided cases test \((.+)\); those cases cannot be traced",
     "威脅模型缺少既有案例所測試的威脅 ID（{0}）；這些案例無法追溯"),
    (r"A test identity credential has the same variable or value as a model credential: (.+)",
     "測試身分的憑證與模型憑證使用相同的變數或值：{0}"),
    (r"The target would reach this console or its database \((.+)\); point it at the application under test",
     "目標會連到本控制台或它的資料庫（{0}）；請改指向受測的應用程式"),
    (r"Test identity credentials are not bound to this target in (\w+) \(NAME=origin\): (.+)",
     "測試身分的憑證沒有在 {0}（NAME=origin）中綁定到此目標：{1}"),
    (r"Scanner resources are not pinned and verified: (.+)", "掃描器資源未經釘選與驗證：{0}"),
    (r"This retest would copy model-designed cases \((.+)\) whose headers the original run's allowed_requests\[\]\.model_headers do not list, "
     r"so the case gate would refuse them\. A retest cannot change the original scope: create a new assessment that lists those header values "
     r"for their method and path, or supply operator-written cases\.",
     "這次複測會複製模型設計的案例（{0}），但它們的 header 不在原執行的 allowed_requests[].model_headers 中，案例閘門會拒絕。"
     "複測不能改變原本的範圍：請建立新的評估，為對應的 method 與 path 列出這些 header 值，或改用操作者撰寫的案例。"),
    (r"Model call failed \(([^)]*)\): (.+)", "模型呼叫失敗（{0}）：{1}"),
    (r"(\w+): operation failed; no successful verification claimed", "{0}：操作失敗；不主張任何驗證成功"),
    (r"Invalid run configuration: (.*)", "執行設定無效：{0}"),
]
_COMPILED = [(re.compile(pattern, re.S), template) for pattern, template in PATTERNS]


def zh(text):
    """The Chinese wording of an English message, or None when the message has no entry."""
    if not isinstance(text, str):
        return None
    if text in ZH:
        return ZH[text]
    for pattern, template in _COMPILED:
        match = pattern.fullmatch(text)
        if match:
            # A group that is itself a known message (for example a wrapped reason) is shown in Chinese too.
            return template.format(*(ZH.get(group, group) for group in match.groups()))
    return None
