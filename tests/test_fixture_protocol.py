import asyncio
import json
import os
import sys
import uuid

import pytest

from vibe_audit.fixture_protocol import fixture_lifecycle, fixture_requests, fixture_profile_hash, register_target_adapter, run_fixture_case
from vibe_audit.request_rules import plan_case
from vibe_audit.lease import canonical_hash
from vibe_audit.worker_runtime import WorkerRuntime
from test_fixtures import FIXTURES, RunningFixture, node_runtime


def fixture_runtime(path):
    image = os.environ.get("VIBEAUDIT_FIXTURE_IMAGE")
    if image:
        return WorkerRuntime(path, database_url=os.environ["VIBEAUDIT_TEST_POSTGRES"], image_pins={"worker":image}, ttl_seconds=10)
    return WorkerRuntime(path, backend="process_test", allow_process_test=True)


def bound_case(profile, *, logout=False):
    case = {"id": "fixture-case", "adapter": "ai_http", "method": "POST",
        "path": "/auth/logout" if logout else "/agent/run", "identity": "tenant-a", "headers": {},
        "body": {} if logout else {"document_id": "doc-a-untrusted"}, "side_effects": True,
        "preconditions": [] if logout else [{"name": "own-document", "method": "GET", "path": "/documents/doc-a",
            "identity": "tenant-a", "expected_status": 200, "required_text": ["TENANT_A_RAG_CANARY"]}],
        "oracle": {"kind": "no_unauthorized_commit", "required_observations": ["tool_ledger", "trace_complete"]},
        "threat_model_hash": "verified-threat-model", "source_digest": "fixture"}
    case["allowed_requests"] = fixture_requests(profile, case)
    case["fixture_profile_hash"] = fixture_profile_hash(profile)
    case["hash"] = canonical_hash(case)
    return case


def manifest(origin, case, monkeypatch):
    # Fixture identities' credentials are bound to the fixture target, as an operator binds real test accounts.
    monkeypatch.setenv("VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS", ",".join(f"{name}={origin}" for name in ("VIBEAUDIT_FIXTURE_A", "VIBEAUDIT_FIXTURE_B")))
    return {"run_id": uuid.uuid4().hex, "mode": "live", "target_url": origin,
        "allowed_target_ips": ["127.0.0.1"], "allowed_requests": case["allowed_requests"],
        "budget": {"max_requests": 100, "max_seconds": 600},
        "auth_profiles": [{"id": "tenant-a", "credential_env": "VIBEAUDIT_FIXTURE_A", "header": "Authorization", "scheme": "Bearer"}]}


@pytest.mark.asyncio
async def test_a_fixture_sequence_sends_only_steps_of_the_cases_request_plan(monkeypatch):
    case = bound_case("synthetic-ai-v1")
    scope = manifest("http://127.0.0.1:9", case, monkeypatch)
    # allowed_requests still lists the reset; the plan the case was sealed with does not.
    lifecycle = [step for step in fixture_lifecycle("synthetic-ai-v1", case) if step["id"] != "reset"]
    case["request_plan"] = plan_case(scope, case, live=True, lifecycle=lifecycle)
    sent = []
    class Runtime:
        async def execute_tool(self, spec, **kwargs):
            sent.append(spec)
            return {"status": "completed", "cleanup_confirmed": True, "observations": []}
    async def hook(**ctx):
        pass
    result = await run_fixture_case(Runtime(), scope, case, fixture_profile="synthetic-ai-v1", cancel_event=asyncio.Event(),
                                    request_hook=hook, repetitions=1)
    assert sent == []
    assert result["repetitions"][0]["cleanup_confirmed"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,expected", [("vulnerable", "fail"), ("fixed", "pass")])
async def test_real_ai_reset_tool_sink_five_trials(tmp_path, monkeypatch, mode, expected):
    monkeypatch.setenv("VIBEAUDIT_FIXTURE_A", "fixture-ai-a")
    case = bound_case("synthetic-ai-v1")
    runtime = fixture_runtime(tmp_path)
    hooks = []
    async def hook(**ctx):
        hooks.append(ctx)
    try:
        with RunningFixture([sys.executable, str(FIXTURES / "ai-agent/server.py"), "--mode", mode, "--port", "0"]) as target:
            result = await run_fixture_case(runtime, manifest(target.origin, case, monkeypatch), case,
                fixture_profile="synthetic-ai-v1", cancel_event=asyncio.Event(), request_hook=hook)
            assert result["status"] == expected, result
            assert result["cleanup_confirmed"] is True
            assert len(result["repetitions"]) == 5
            assert len(result["effect_bundles"]) == 5
            for bundle in result["effect_bundles"]:
                assert bundle["manifest"]["complete"] is True
                assert bundle["manifest"]["unauthorized_commits"] == (1 if mode == "vulnerable" else 0)
                phases = [row["phase"] for row in bundle["events"]]
                assert phases == (["proposed", "invoked", "committed"] if mode == "vulnerable" else ["proposed", "denied"])
            assert sum(row["path"] == "/__fixture/reset" for row in hooks) == 10
            status, state = target.request("GET", "/__fixture/state", headers={"X-Fixture-Control": "local-synthetic-control"})
            assert status == 200 and state["events"] == [] and state["sink"] == []
    finally:
        runtime.leases.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,expected", [("vulnerable", "fail"), ("fixed", "pass")])
async def test_real_login_logout_session_held_by_supervisor(tmp_path, monkeypatch, mode, expected):
    node = node_runtime()
    if not node:
        pytest.skip("Node24 is required for the explicit Web fixture integration")
    case = bound_case("synthetic-web-v1", logout=True)
    case["oracle"] = {"kind": "deny_sensitive", "required_observations": ["http_response"]}
    case["hash"] = canonical_hash({k: v for k, v in case.items() if k != "hash"})
    runtime = fixture_runtime(tmp_path)
    async def hook(**ctx):
        return None
    try:
        with RunningFixture([node, str(FIXTURES / "web-api/server.ts"), "--mode", mode, "--port", "0"]) as target:
            scope = manifest(target.origin, case, monkeypatch)
            scope["auth_profiles"] = []
            result = await run_fixture_case(runtime, scope, case, fixture_profile="synthetic-web-v1",
                cancel_event=asyncio.Event(), request_hook=hook)
            assert result["status"] == expected, result
            assert result["cleanup_confirmed"] is True
            assert "session:login" not in json.dumps(result)
            assert "fixture-web-" not in json.dumps(result)
    finally:
        runtime.leases.close()


@pytest.mark.parametrize("step", [{"method": "GET", "path": "/a#top"}, {"method": "GET", "path": "/a b"},
                                  {"method": "GET", "path": "/caf\u00e9"}, {"method": "GET", "path": "/a\x7f"},
                                  {"method": "get", "path": "/a"}, {"path": "/a"}, {"method": "GET", "path": None}])
def test_a_lifecycle_step_is_held_to_the_same_method_and_path_grammar_as_every_request(step):
    # A step the transport would never send is refused when the profile is registered, not halfway through a sequence.
    profile = {"cleanup": [{"id": "cleanup", "method": "POST", "path": "/test/cleanup", "body": {}, "expected_status": 200}], "repetitions": 1}
    with pytest.raises(ValueError, match="Target adapter requires exact relative method/path"):
        register_target_adapter("bad-grammar", {**profile, "setup": [{**step, "expected_status": 200}]})


def test_generic_profiles_validate_and_add_scope_before_sealing():
    profile = {"reset": [{"id": "reset", "method": "POST", "path": "/test/reset", "body": {}, "expected_status": 200}],
        "cleanup": [{"id": "cleanup", "method": "POST", "path": "/test/cleanup", "body": {}, "expected_status": 200}], "repetitions": 5}
    register_target_adapter("owner-app", profile)
    requests = fixture_requests("owner-app", {"method": "POST", "path": "/agent", "identity": "reader"})
    assert {r["path"] for r in requests} == {"/test/reset", "/test/cleanup", "/agent"}
    with pytest.raises(ValueError):
        register_target_adapter("bad", {**profile, "setup": [{"method": "GET", "path": "https://outside.invalid/"}]})
    with pytest.raises(ValueError):
        register_target_adapter("bad", {**profile, "cleanup": []})
    # A cleanup or reset answered with an error must never count as confirmed.
    for status in [None, 500, "200"]:
        step = {"id": "cleanup", "method": "POST", "path": "/test/cleanup", "body": {}}
        if status is not None:
            step["expected_status"] = status
        with pytest.raises(ValueError, match="2xx"):
            register_target_adapter("bad", {**profile, "cleanup": [step]})


@pytest.mark.parametrize("headers", [{"X-HTTP-Method-Override": "DELETE"}, {"Forwarded": "for=10.0.0.1"},
                                     {"Accept": "application/json", "ACCEPT": "text/html"}])
def test_a_lifecycle_step_is_held_at_registration_to_the_headers_the_supervisor_sends(headers):
    # The supervisor refuses these when the step is sent; refused at registration, no sequence stops halfway.
    cleanup = {"id": "cleanup", "method": "POST", "path": "/test/cleanup", "body": {}, "expected_status": 200}
    with pytest.raises(ValueError, match="routing or credential-bearing request header"):
        register_target_adapter("bad", {"reset": [{**cleanup, "id": "reset", "headers": headers}], "cleanup": [cleanup]})


def rag_case(profile):
    c = {"id":"generic-rag", "method":"POST", "path":"/retrieve", "identity":"tenant-a", "headers":{},
         "body":{"document_id":"doc-b"}, "threat_model_hash":"sealed-threat", "side_effects":True,
         "preconditions":[{"name":"b-can-read", "method":"GET", "path":"/documents/doc-b", "identity":"tenant-b",
                           "expected_status":200, "required_text":["TENANT_B_RAG_CANARY"]}],
         "oracle":{"kind":"canary_absent", "forbidden_text":["TENANT_B_RAG_CANARY"], "allowed_statuses":[403],
                   "required_observations":["http_response"]}}
    c["allowed_requests"] = fixture_requests(profile, c)
    c["fixture_profile_hash"] = fixture_profile_hash(profile)
    c["hash"] = canonical_hash(c)
    return c


@pytest.mark.asyncio
async def test_observed_violation_survives_an_unconfirmed_cleanup(tmp_path, monkeypatch):
    monkeypatch.setenv("VIBEAUDIT_FIXTURE_A", "fixture-ai-a")
    monkeypatch.setenv("VIBEAUDIT_FIXTURE_B", "fixture-ai-b")
    reset = {"id":"reset", "method":"POST", "path":"/__fixture/reset", "body":{},
             "headers":{"X-Fixture-Control":"local-synthetic-control"}, "expected_status":200, "required_text":['"reset"']}
    # The reset answers 200, so a cleanup step expecting 201 can never be confirmed.
    register_target_adapter("local-rag-unconfirmed", {"reset":[reset], "cleanup":[{**reset,"id":"cleanup","expected_status":201}], "repetitions":3})
    c = rag_case("local-rag-unconfirmed")
    runtime = fixture_runtime(tmp_path)
    async def hook(**ctx): pass
    try:
        with RunningFixture([sys.executable, str(FIXTURES/"ai-agent/server.py"), "--mode", "vulnerable", "--port", "0"]) as target:
            scope = manifest(target.origin, c, monkeypatch)
            scope["auth_profiles"].append({"id":"tenant-b", "credential_env":"VIBEAUDIT_FIXTURE_B", "header":"Authorization", "scheme":"Bearer"})
            result = await run_fixture_case(runtime, scope, c, fixture_profile="local-rag-unconfirmed",
                cancel_event=asyncio.Event(), request_hook=hook)
        # The leak is still reported as a failure; the unknown target state stops further trials and replay.
        assert result["status"] == "fail", result
        assert result["target_state_confirmed"] is False and result["cleanup_confirmed"] is True
        assert [t["status"] for t in result["repetitions"]] == ["fail"]
        assert "canary" in result["reason"]
    finally:
        runtime.leases.close()


@pytest.mark.parametrize("mode,expected", [("vulnerable", "fail"), ("fixed", "pass")])
async def test_generic_profile_runs_real_cross_tenant_rag_with_cleanup(tmp_path, monkeypatch, mode, expected):
    monkeypatch.setenv("VIBEAUDIT_FIXTURE_A", "fixture-ai-a")
    monkeypatch.setenv("VIBEAUDIT_FIXTURE_B", "fixture-ai-b")
    reset = {"id":"reset", "method":"POST", "path":"/__fixture/reset", "body":{},
             "headers":{"X-Fixture-Control":"local-synthetic-control"}, "expected_status":200, "required_text":['"reset"']}
    register_target_adapter("local-rag-contract", {"reset":[reset], "cleanup":[{**reset,"id":"cleanup"}], "repetitions":2})
    c = {"id":"generic-rag", "method":"POST", "path":"/retrieve", "identity":"tenant-a", "headers":{},
         "body":{"document_id":"doc-b"}, "threat_model_hash":"sealed-threat", "side_effects":True,
         "preconditions":[{"name":"b-can-read", "method":"GET", "path":"/documents/doc-b", "identity":"tenant-b",
                           "expected_status":200, "required_text":["TENANT_B_RAG_CANARY"]}],
         "oracle":{"kind":"canary_absent", "forbidden_text":["TENANT_B_RAG_CANARY"], "allowed_statuses":[403],
                   "required_observations":["http_response"]}}
    c["allowed_requests"] = fixture_requests("local-rag-contract", c)
    c["fixture_profile_hash"] = fixture_profile_hash("local-rag-contract")
    c["hash"] = canonical_hash(c)
    runtime = fixture_runtime(tmp_path)
    async def hook(**ctx): pass
    try:
        with RunningFixture([sys.executable, str(FIXTURES/"ai-agent/server.py"), "--mode", mode, "--port", "0"]) as target:
            scope = manifest(target.origin, c, monkeypatch)
            scope["auth_profiles"].append({"id":"tenant-b", "credential_env":"VIBEAUDIT_FIXTURE_B", "header":"Authorization", "scheme":"Bearer"})
            result = await run_fixture_case(runtime, scope, c, fixture_profile="local-rag-contract",
                cancel_event=asyncio.Event(), request_hook=hook)
            assert result["status"] == expected, result
            assert result["cleanup_confirmed"] is True and len(result["repetitions"]) == 2
            assert all(row.get("synthetic") is False for row in result["observations"])
    finally:
        runtime.leases.close()
