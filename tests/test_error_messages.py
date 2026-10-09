"""Every fixed error message the backend reports has Traditional Chinese wording for the console."""
import ast
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vibe_audit.api import create_app
from vibe_audit.messages import PATTERNS, STATUS_ZH, ZH, zh

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend" / "vibe_audit"
# The source scans below read the checkout. Mutation testing (scripts/mutation-test.py) runs a copy of the tests
# next to a mutated copy of the package, where there is no checkout to scan.
from_checkout = pytest.mark.skipif(not BACKEND.is_dir(), reason="the backend sources are not next to these tests")
CJK = re.compile(r"[一-鿿]")
RAISERS = {"PolicyError", "HTTPException", "problem", "AdapterBlocked", "ProviderError", "CatalogError", "LeaseError"}
# Calls whose first message argument is shown to the operator: activity events, snapshot gaps and run gaps.
REPORTERS = {"event": 1, "gap": 0}
# The separate benchmark tool and the table itself report nothing to the console.
SKIPPED_MODULES = {"benchmark.py", "benchmark_matching.py", "messages.py"}
def sample(node, top=True):
    """The message a site produces, with each run-specific value replaced by a placeholder."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(part.value if isinstance(part, ast.Constant) else "1" for part in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return sample(node.left, False) + sample(node.right, False)
    if isinstance(node, ast.GeneratorExp):
        return sample(node.elt, top)
    return None if top else "1"


def message_args(node):
    """The message arguments of one AST node, if it reports a message to the operator."""
    if isinstance(node, ast.Call):
        name = getattr(node.func, "id", getattr(node.func, "attr", None))
        if name in RAISERS:
            args = [arg for arg in node.args if not (isinstance(arg, ast.Constant) and isinstance(arg.value, int))]
            args += [keyword.value for keyword in node.keywords if keyword.arg == "detail"]
            return args[:1]
        if name in REPORTERS and len(node.args) > REPORTERS[name]:
            return [node.args[REPORTERS[name]]]
        target = getattr(node.func, "value", None)
        gaps = (isinstance(target, ast.Subscript) and getattr(target.slice, "value", None) == "gaps") or getattr(target, "id", None) == "gaps"
        if name in {"append", "extend"} and gaps:
            return node.args[:1]
        return [keyword.value for keyword in node.keywords if keyword.arg == "reason"]
    if isinstance(node, ast.Dict):
        return [value for key, value in zip(node.keys, node.values) if getattr(key, "value", None) == "reason"]
    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Tuple):
        names = [getattr(target, "id", None) for target in getattr(node.targets[0], "elts", [])]
        return [node.value.elts[names.index("reason")]] if "reason" in names else []
    return []


def raise_sites():
    for path in sorted(BACKEND.glob("*.py")):
        if path.name in SKIPPED_MODULES:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            # Either branch of a conditional message is reported.
            args = [side for arg in message_args(node) for side in ([arg.body, arg.orelse] if isinstance(arg, ast.IfExp) else [arg])]
            for arg in args:
                if not (isinstance(arg, ast.Constant) and arg.value in ("", None)):
                    yield pytest.param(arg, id=f"{path.name}:{arg.lineno}:{arg.col_offset}")


def candidates(node):
    """The messages an argument can carry. A bare variable, field or call passes on text written elsewhere: another
    message (checked where it is written) or untrusted repository, model, scanner or target text, which stays as it is.
    Only the fixed fallbacks of such expressions (`x or "..."`, `.get(k, "...")`, `next(..., "...")`) are messages here."""
    text = sample(node)
    if text is not None:
        return [text]
    if isinstance(node, ast.BoolOp):
        return [text for value in node.values for text in candidates(value)]
    if isinstance(node, ast.Call) and len(node.args) == 2 and getattr(node.func, "attr", getattr(node.func, "id", None)) in {"get", "next"}:
        return candidates(node.args[1])
    return []


@from_checkout
@pytest.mark.parametrize("message", list(raise_sites()))
def test_every_reported_message_has_chinese_wording(message):
    for text in candidates(message):
        # "<value>: <value>" joins a label and a message that are both reported, and checked, elsewhere.
        if re.fullmatch(r"1: 1( — 1)?", text):
            continue
        assert zh(text) is not None, f"no Chinese wording for: {text}"


def test_messages_built_in_two_steps_have_chinese_wording():
    # policy.py builds this gap in a variable before adding it.
    assert zh("Automated threats without a provided case were not tested: T-001") == "沒有提供案例的自動化威脅未經測試：T-001"


def test_every_engine_written_text_of_the_demo_run_reads_in_chinese():
    import json
    run = json.loads((ROOT / "docs" / "sample-report.json").read_text(encoding="utf-8"))
    threats = run["threat_model"]["threats"]
    texts = [event["message"] for event in run["events"]] + run["gaps"] + [finding["title"] for finding in run["findings"]]
    texts += [execution["reason"] for execution in run["executions"]] + [case["title"] for case in run["cases"]]
    texts += [threat[key] for threat in threats for key in ("title", "category", "invariant", "impact")]
    missing = sorted({text for text in texts if zh(text) is None})
    assert not missing, f"engine-written demo text without Chinese wording: {missing}"


@from_checkout
def test_chinese_wording_is_chinese_and_every_entry_is_used():
    source = "\n".join(path.read_text(encoding="utf-8") for path in BACKEND.glob("*.py") if path.name != "messages.py")
    # Starlette writes these two itself.
    unused = [message for message in ZH if message not in source and message not in {"Not Found", "Method Not Allowed"}]
    assert not unused, f"entries no backend code reports: {unused}"
    for chinese in [*ZH.values(), *(template for _, template in PATTERNS)]:
        # A template may only rearrange its values with Chinese punctuation.
        assert CJK.search(chinese) or "：" in chinese, chinese
    assert not any(c in chinese for chinese in ZH.values() for c in "们这个对说为时问进"), "use Traditional Chinese"


def test_dynamic_messages_keep_their_values():
    assert zh("Automated threats without cases: T-001, T-002") == "自動化威脅沒有對應的案例：T-001, T-002"
    assert zh("Scanner resources are not pinned and verified: Isolated runtime unavailable") == "掃描器資源未經釘選與驗證：隔離執行環境無法使用"
    assert zh("Model call failed (rate_limited): Provider rate limit") == "模型呼叫失敗（rate_limited）：Provider rate limit"
    assert zh("A message from a target") is None and zh(None) is None


def test_label_and_message_joins_read_each_side_on_its_own():
    # The label, the status and the message each decide on their own; the split is at the first colon.
    assert zh("C-1: pass") == "C-1：未觀測到違規"
    assert zh("Note: Model refused the request") == "Note：模型拒絕了請求"
    assert zh("Excluded directory: x: y") == "排除的目錄：x: y"
    assert zh("Note: whatever") is None and zh("pass") is None


def test_api_errors_carry_chinese_detail(tmp_path):
    client = TestClient(create_app(data_dir=tmp_path, testing=True))
    blocked = client.get("/api/runs")
    assert blocked.status_code == 401
    assert blocked.json() == {"detail": "Local session required", "detail_zh": "需要本機 session"}
    csrf = client.get("/api/session", headers={"X-VibeAudit-Token": client.app.state.session_token}).json()["csrf_token"]
    client.headers["X-CSRF-Token"] = csrf
    # RunNotFound and Starlette's own 404 and 405 carry the Chinese wording too.
    assert client.get("/api/runs/no-such-run").json() == {"detail": "Run or artifact not found", "detail_zh": "找不到該執行或產物"}
    unknown = client.get("/api/no-such-route")
    assert unknown.status_code == 404 and unknown.json() == {"detail": "Not Found", "detail_zh": "找不到"}
    assert client.put("/api/runs").json() == {"detail": "Method Not Allowed", "detail_zh": "不允許此方法"}
    # The console reads the same table; GET /api/messages needs the session like every other route.
    table = client.get("/api/messages").json()
    assert table == {"exact": ZH, "status": STATUS_ZH, "patterns": [list(pair) for pair in PATTERNS]}
    for pattern, _ in PATTERNS:
        # Patterns are read by JavaScript too: no Python-only group, flag or lookbehind syntax.
        assert not re.search(r"\(\?(P|<[=!]|[aiLmsux])", pattern), pattern


def test_chinese_report_shows_the_run_error_in_chinese():
    import json
    from vibe_audit.service import report_markdown
    run = json.loads((ROOT / "docs" / "sample-report.json").read_text(encoding="utf-8"))
    run["error"] = "Model call budget exhausted"
    assert "錯誤：模型呼叫預算已用完" in report_markdown(run, "zh-Hant")
    assert "Error: Model call budget exhausted" in report_markdown(run, "en")
