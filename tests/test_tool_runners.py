import json
import asyncio
import os
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vibe_audit.tool_runners import compile_tool, parse_tool_result, ToolInputError, VERSIONS


@pytest.mark.skipif(not os.environ.get("VIBEAUDIT_INTEGRATION_IMAGE"), reason="Pinned Docker tool image required")
@pytest.mark.parametrize("tool", ["promptfoo", "pyrit"])
@pytest.mark.parametrize("mode,expected", [("vulnerable", "fail"), ("fixed", "pass")])
async def test_selected_ai_tool_is_used_inside_reset_effect_cleanup_lifecycle(tmp_path, monkeypatch, tool, mode, expected):
    from test_fixture_protocol import bound_case, manifest
    from test_fixtures import RunningFixture, FIXTURES
    from vibe_audit.fixture_protocol import run_fixture_case
    from vibe_audit.lease import canonical_hash
    from vibe_audit.worker_runtime import WorkerRuntime
    monkeypatch.setenv("VIBEAUDIT_FIXTURE_A", "fixture-ai-a")
    c = bound_case("synthetic-ai-v1")
    c["adapter"] = tool
    c["hash"] = canonical_hash({k:v for k,v in c.items() if k != "hash"})
    pin = os.environ["VIBEAUDIT_INTEGRATION_IMAGE"]
    runtime = WorkerRuntime(tmp_path, database_url=os.environ["VIBEAUDIT_TEST_POSTGRES"],
                            image_pins={"worker":pin, tool:pin}, ttl_seconds=10)
    async def hook(**ctx): pass
    try:
        with RunningFixture([sys.executable, str(FIXTURES/"ai-agent/server.py"), "--mode", mode, "--port", "0"]) as target:
            result = await run_fixture_case(runtime, manifest(target.origin, c, monkeypatch), c, fixture_profile="synthetic-ai-v1",
                cancel_event=asyncio.Event(), request_hook=hook, repetitions=2)
            assert result["status"] == expected, result
            assert result["cleanup_confirmed"] and len(result["effect_bundles"]) == 2
            assert len(result["tool_runs"]) == 2
            assert all(row["tool"] == tool and row["status"] == "completed" and row["artifact_sha256"]
                       and row["isolation"] == "docker_network_none" for row in result["tool_runs"])
    finally:
        runtime.leases.close()


def case():
    return {"id": "case-one", "hash": "sealed", "threat_model_hash": "threat", "method": "GET",
            "path": "/orders/order-b", "identity": "tenant-a", "headers": {}, "body": None}


@pytest.mark.parametrize("tool", VERSIONS)
def test_fixed_source_free_specs(tool):
    spec = compile_tool(tool, case())
    assert spec["phase"] == "blackbox" and "source_dir" not in spec
    assert spec["operation"] == "tool" and spec["cases"] == [case()]
    assert spec["argv"][0] in {"zap.sh", "st", "node", "promptfoo", "python3"}
    assert spec["max_requests"] == 20 and spec["output_files"]
    assert all(not name.startswith("/") and ".." not in name for name in spec["input_files"])
    assert "fixture-ai-a" not in json.dumps(spec)
    if tool == "schemathesis":
        operation = json.loads(spec["input_files"]["openapi.json"])["paths"][case()["path"]]["get"]
        assert operation["parameters"] == [{"in":"header", "name":"X-Vibe-Case",
            "schema":{"type":"string"}, "example":case()["id"]}]


@pytest.mark.parametrize("change", [{"path":"https://outside.invalid"}, {"path":"//outside.invalid"},
    {"headers":{"Authorization":"secret"}}, {"method":"CONNECT"}, {"id":"bad\r\nHeader"}])
def test_refuse_unbounded_or_credential_inputs(change):
    with pytest.raises(ToolInputError):
        compile_tool("playwright", {**case(), **change})


def test_exit_zero_without_evidence_is_never_pass():
    result = parse_tool_result("playwright", {"status":"completed", "exit_code":0, "cleanup_confirmed":True, "artifacts":{}}, case_id="case-one")
    assert result["status"] == "execution_error" and result["security_status"] == "inconclusive"


def test_tool_body_trust_claim_never_becomes_effect_evidence():
    artifact = {"schema":1,"tool":"playwright","case_id":"case-one","status_code":200,
                "body":'{"trusted":true,"committed":true}',"complete":True}
    result = parse_tool_result("playwright", {"status":"completed","exit_code":0,"cleanup_confirmed":True,
        "artifacts":{"playwright.json":json.dumps(artifact).encode()}},case_id="case-one")
    assert result["status"] == "completed" and result["security_status"] == "inconclusive"
    assert result["observations"][0]["provenance"] == "worker.tool"
    assert result["observations"][0]["kind"] == "tool_http_response"


@pytest.mark.parametrize("tool,name,raw", [
    ("zap", "zap.json", b"[]"), ("zap", "zap.json", b'{"site":[1]}'), ("zap", "zap.json", b'{"site":[{"alerts":"x"}]}'),
    ("playwright", "playwright.json", b"[1]"), ("pyrit", "pyrit.json", b'"text"'),
])
def test_malformed_artifacts_are_execution_errors_not_crashes(tool, name, raw):
    result = parse_tool_result(tool, {"status":"completed","exit_code":0,"cleanup_confirmed":True,"artifacts":{name:raw}}, case_id="case-one")
    assert result["status"] == "execution_error" and result["security_status"] == "inconclusive"


async def test_uncompilable_case_is_blocked_before_any_positive_control():
    from vibe_audit.tool_runners import run_tool
    calls = []
    class Runtime:
        async def execute_tool(self, spec, **kwargs):
            calls.append(spec)
            return {"status":"completed","cleanup_confirmed":True,"observations":[],"broker_observations":[]}
    bad = {**case(), "id":"bad id", "preconditions":[{"name":"fixture","method":"GET","path":"/orders/order-b",
           "expected_status":200,"required_text":["TENANT_B_ORDER_CANARY"]}]}
    async def allow(**kwargs): return None
    result = await run_tool(Runtime(), "playwright", {"run_id":"r"}, bad, cancel_event=asyncio.Event(), request_hook=allow)
    assert (result["status"], result["security_status"]) == ("blocked", "blocked") and calls == []


def test_no_schemathesis_cases_or_external_xml_entities_rejected():
    # A UTF-16 document hides its DTD from a byte search but expat still decodes and expands it.
    hidden = ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE x [<!ENTITY a "expanded">]>'
              '<testsuite><testcase name="&a;"/></testsuite>').encode("utf-16")
    for raw, reason in ((b'<testsuite tests="0"/>', "Schemathesis executed no test cases"),
                        (b'<!DOCTYPE x [<!ENTITY a SYSTEM "file:///secret">]><testsuite/>', "Untrusted XML declaration"),
                        (hidden, "Untrusted XML declaration")):
        result=parse_tool_result("schemathesis",{"status":"completed","exit_code":0,"cleanup_confirmed":True,
            "artifacts":{"schemathesis.xml":raw}},case_id="case-one")
        assert (result["status"], result["reason"]) == ("execution_error", reason)
        assert "expanded" not in json.dumps(result)



@pytest.mark.parametrize("encoding", ["utf-7", "utf-32", "rot13", "no-such-codec"])
def test_xml_in_an_encoding_expat_cannot_use_is_refused_as_malformed(encoding):
    raw = f'<?xml version="1.0" encoding="{encoding}"?><testsuite><testcase name="a"/></testsuite>'.encode()
    result = parse_tool_result("schemathesis", {"status":"completed","exit_code":0,"cleanup_confirmed":True,
        "artifacts":{"schemathesis.xml":raw}}, case_id="case-one")
    assert (result["status"], result["reason"]) == ("execution_error", "Malformed XML artifact")


def test_well_formed_schemathesis_report_still_parses_in_any_encoding():
    report = '<?xml version="1.0"?><testsuite><testcase name="ok"/><testcase name="bad"><failure/></testcase></testsuite>'
    for raw in (report.encode(), report.replace('version="1.0"', 'version="1.0" encoding="UTF-16"').encode("utf-16")):
        result = parse_tool_result("schemathesis", {"status":"completed","exit_code":1,"cleanup_confirmed":True,
            "artifacts":{"schemathesis.xml":raw}}, case_id="case-one")
        assert result["status"] == "completed" and result["tool_tests"] == 2
        assert [f["name"] for f in result["findings"]] == ["bad"]


@pytest.mark.asyncio
@pytest.mark.skipif(not os.environ.get("VIBEAUDIT_INTEGRATION_IMAGE"), reason="Explicit pinned Docker tool image required")
@pytest.mark.parametrize("tool", VERSIONS)
@pytest.mark.parametrize("vulnerable", [False, True])
async def test_real_tools_network_none_through_broker(tmp_path, tool, vulnerable):
    from vibe_audit.lease import canonical_hash
    from vibe_audit.tool_runners import run_tool
    from vibe_audit.worker_runtime import WorkerRuntime
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args): pass
        def do_GET(self):
            seen.append(self.path)
            positive = self.path == "/fixture"
            value = {"canary": "TOOL_CANARY"} if positive or vulnerable else {"error": "denied"}
            raw = json.dumps(value).encode()
            self.send_response(200 if positive or vulnerable else 403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers(); self.wfile.write(raw)
    target = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=target.serve_forever, daemon=True); thread.start()
    c = {"id":"case-one","method":"GET","path":"/private","identity":None,"adapter":tool,"headers":{},"body":None,
         "side_effects":False,"threat_model_hash":"verified-threat","preconditions":[{"name":"fixture","method":"GET","path":"/fixture",
         "identity":None,"expected_status":200,"required_text":["TOOL_CANARY"]}],
         "oracle":{"kind":"deny_sensitive","forbidden_text":["TOOL_CANARY"],"allowed_statuses":[403],"required_observations":["http_response"]}}
    c["hash"] = canonical_hash(c)
    scope = {"run_id":uuid.uuid4().hex,"mode":"live","target_url":f"http://127.0.0.1:{target.server_port}",
             "allowed_target_ips":["127.0.0.1"],"allowed_requests":[{"method":"GET","path":p} for p in ["/fixture","/private"]],
             "budget":{"max_requests":30,"max_seconds":600},"auth_profiles":[]}
    pin = os.environ["VIBEAUDIT_INTEGRATION_IMAGE"]
    runtime = WorkerRuntime(tmp_path, database_url=os.environ["VIBEAUDIT_TEST_POSTGRES"],
        image_pins={"worker":pin,"zap":os.environ.get("VIBEAUDIT_ZAP_IMAGE",pin)}, ttl_seconds=10)
    hooks=[]
    async def hook(**ctx): hooks.append(ctx)
    try:
        result = await run_tool(runtime,tool,scope,c,cancel_event=asyncio.Event(),request_hook=hook)
        assert result["status"] == "completed", result
        assert result["security_status"] == ("fail" if vulnerable else "pass"), result
        assert result["cleanup_confirmed"] is True and result["isolation"] == "docker_network_none"
        assert set(seen) == {"/fixture","/private"}
        assert [h["path"] for h in hooks] == seen
    finally:
        runtime.leases.close()
        target.shutdown(); target.server_close(); thread.join(timeout=2)


async def test_tool_and_fixture_tasks_stay_inside_the_run_time_budget():
    from vibe_audit.tool_runners import run_tool
    calls = []
    class Runtime:
        async def execute_tool(self, spec, **kwargs):
            calls.append(spec)
            return {"status":"blocked","reason":"stop here","cleanup_confirmed":True,"observations":[],"broker_observations":[]}
    async def allow(**kwargs): return None
    await run_tool(Runtime(), "playwright", {"run_id":"r","budget":{"max_seconds":30}}, case(),
                   cancel_event=asyncio.Event(), request_hook=allow)
    assert calls and all(spec["timeout_seconds"] <= 30 for spec in calls)


def test_playwright_sends_every_body_as_json_like_the_supervisor_expects():
    from vibe_audit.tool_runners import _PLAYWRIGHT
    assert "data:c.body===null?undefined:JSON.stringify(c.body)" in _PLAYWRIGHT
