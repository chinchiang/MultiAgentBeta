"""Every fixed error message the backend reports has Traditional Chinese wording for the console."""
import ast
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vibe_audit.api import create_app
from vibe_audit.messages import PATTERNS, ZH, zh

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend" / "vibe_audit"
CJK = re.compile(r"[一-鿿]")
RAISERS = {"PolicyError", "HTTPException", "problem"}
# Arguments that pass on a message written elsewhere (an adapter, a runtime probe, an exception handler); those
# messages stay English unless they also have an entry.
PASSED_ON = {"str(exc)", "capabilities.get('reason', 'Isolated runtime unavailable')", "exc.detail"}


def sample(node):
    """The message a raise site produces, with each run-specific value replaced by a placeholder."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(part.value if isinstance(part, ast.Constant) else "1" for part in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = sample(node.left), sample(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.Call):
        return "X1, X2"
    return None


def raise_sites():
    for path in sorted(BACKEND.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", getattr(node.func, "attr", None))
            if name not in RAISERS:
                continue
            args = [arg for arg in node.args if not (isinstance(arg, ast.Constant) and isinstance(arg.value, int))]
            args += [keyword.value for keyword in node.keywords if keyword.arg == "detail"]
            if args:
                yield pytest.param(args[0], id=f"{path.name}:{node.lineno}")


@pytest.mark.parametrize("message", list(raise_sites()))
def test_every_raised_message_has_chinese_wording(message):
    source = ast.unparse(message)
    if source in PASSED_ON:
        return
    text = sample(message)
    assert text is not None, f"cannot read the message of {source}; add it to PASSED_ON only if it passes on another message"
    assert zh(text) is not None, f"no Chinese wording for: {text}"


def test_chinese_wording_is_chinese_and_every_entry_is_used():
    source = "\n".join(path.read_text(encoding="utf-8") for path in BACKEND.glob("*.py") if path.name != "messages.py")
    # Starlette writes these two itself.
    unused = [message for message in ZH if message not in source and message not in {"Not Found", "Method Not Allowed"}]
    assert not unused, f"entries no backend code reports: {unused}"
    for chinese in [*ZH.values(), *(template for _, template in PATTERNS)]:
        assert CJK.search(chinese), chinese
    assert not any(c in chinese for chinese in ZH.values() for c in "们这个对说为时问进"), "use Traditional Chinese"


def test_dynamic_messages_keep_their_values():
    assert zh("Automated threats without cases: T-001, T-002") == "自動化威脅沒有對應的案例：T-001, T-002"
    assert zh("Scanner resources are not pinned and verified: Isolated runtime unavailable") == "掃描器資源未經釘選與驗證：隔離執行環境無法使用"
    assert zh("Model call failed (rate_limited): Provider rate limit") == "模型呼叫失敗（rate_limited）：Provider rate limit"
    assert zh("A message from a target") is None and zh(None) is None


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


def test_chinese_report_shows_the_run_error_in_chinese():
    import json
    from vibe_audit.service import report_markdown
    run = json.loads((ROOT / "docs" / "sample-report.json").read_text(encoding="utf-8"))
    run["error"] = "Model call budget exhausted"
    assert "錯誤：模型呼叫預算已用完" in report_markdown(run, "zh-Hant")
    assert "Error: Model call budget exhausted" in report_markdown(run, "en")
