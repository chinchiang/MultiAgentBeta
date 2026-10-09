"""Regression checks for boundaries found during the local integration audit."""
import base64
import copy
import sys

import pytest

from vibe_audit import adapters
from vibe_audit.domain import RunInput
from vibe_audit.policy import PolicyError
from vibe_audit.service import Engine, report_markdown
from vibe_audit.store import Store
from vibe_audit.worker_entry import Supervisor


def supervisor(monkeypatch):
    monkeypatch.setitem(sys.modules, "adapters", adapters)
    instance = Supervisor.__new__(Supervisor)
    instance.manifest = {"allowed_requests":[{"method":"POST","path":"/resource"}],"auth_profiles":[]}
    instance.spec = {"operation":"tool","cases":[{"id":"C1","method":"POST","path":"/resource",
        "identity":None,"headers":{"X-Fixture-Control":"sealed"},"body":{"tenant":"A","limit":1}}]}
    instance.sessions = {}
    return instance


def request(body=b'{"tenant":"A","limit":1}', headers=None):
    return {"case_id":"C1","method":"POST","path":"/resource","identity":None,
            "headers":headers or {"X-Fixture-Control":"sealed","Content-Type":"application/json"},
            "body_b64":base64.b64encode(body).decode()}


@pytest.mark.parametrize("body", [
    b'{"tenant":"B","limit":1}', b'{"tenant":"A","limit":true}',
    b'{"tenant":"B","tenant":"A","limit":1}', b'',
])
def test_supervisor_rejects_body_mutation_before_dispatch(monkeypatch, body):
    with pytest.raises(ValueError):
        supervisor(monkeypatch).allowed_request(request(body))


def test_supervisor_allows_only_planned_headers_and_json(monkeypatch):
    instance = supervisor(monkeypatch)
    valid = request(b'{ "limit": 1, "tenant": "A" }')
    assert instance.allowed_request(valid)[2:4] == ("POST", "/resource")
    for headers in ({"X-Fixture-Control":"different"},
                    {"X-Fixture-Control":"sealed","X-Escalate":"admin"}):
        with pytest.raises(ValueError):
            instance.allowed_request(request(headers=headers))


def test_report_markdown_never_interprets_untrusted_html_or_links():
    run = {"name":'<script>alert(1)</script>',"id":"r","mode":"demo","status":"complete",
        "findings":[{"severity":"high","state":"hypothesis",
        "title":"[click](javascript:alert(1))","evidence_ids":["e"]}],
        "gaps":["<img src=x onerror=alert(1)>"],"executions":[],
        "limitations":["General bound, not an omitted case"]}
    report = report_markdown(run)
    assert "<script>" not in report and "<img " not in report
    assert "[click](javascript:" not in report
    assert "Capability limits" in report
    assert run["name"].startswith("<script>")


def test_chinese_report_uses_chinese_wording_and_escapes_the_same_way():
    run = {"name":'<script>alert(1)</script>',"id":"r","mode":"demo","status":"incomplete",
        "report_note":"SYNTHETIC DEMO ONLY: not real model or application validation",
        "findings":[{"severity":"high","state":"hypothesis","title":"[click](javascript:alert(1))","evidence_ids":["e1","e2"]}],
        "gaps":["<img src=x onerror=alert(1)>"],"executions":[{"case_id":"C-1","status":"outcome_unknown","reason":"sent"}],
        "limitations":["General bound"],"manifest":{"parent_run_id":"p1","parent_finding_ids":["f1"]}}
    report = report_markdown(run, "zh-Hant")
    assert "<script>" not in report and "<img " not in report and "[click](javascript:" not in report
    for text in ("## 發現", "## 涵蓋缺口", "## 執行紀錄", "## 能力限制", "模式：合成示範｜狀態：未完整完成", "- [高 / 待驗證假設]",
                 "  證據：e1、e2", "- C-1: 結果不明", "複測對象：p1（發現：f1）", "僅為合成示範：不是真實模型或應用程式的驗證"):
        assert text in report, text
    # An unknown code is shown as it is rather than dropped.
    assert "[mystery / hypothesis]" in report_markdown({**run, "findings":[{**run["findings"][0], "severity":"mystery"}]})
    with pytest.raises(ValueError):
        report_markdown(run, "fr")


async def test_optional_reporter_can_order_but_cannot_invent_findings(tmp_path):
    store = Store(tmp_path)
    engine = Engine(store)
    run = engine.create(RunInput())
    engine.start(run["id"])
    await engine.tasks[run["id"]]
    run = store.get(run["id"])
    run["mode"] = "live"
    run["manifest"]["models"].append({"id":"reporter","role":"reporter"})
    original = copy.deepcopy(run["findings"])
    async def valid(*args):
        return {"finding_ids":[f["id"] for f in reversed(original)]}
    engine.model = valid
    await engine._report(run)
    assert run["findings"] == list(reversed(original))
    run.pop("report_order")
    async def invalid(*args):
        return {"finding_ids":["fabricated"]}
    engine.model = invalid
    with pytest.raises(PolicyError):
        await engine._report(run)
    assert {f["id"] for f in run["findings"]} == {f["id"] for f in original}
    store.close()
