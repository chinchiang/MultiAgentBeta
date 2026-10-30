"""Regression checks for the 2026-10-31 cross-stage review findings."""
import copy
import json
from collections import defaultdict

import pytest
from fastapi.testclient import TestClient

from vibe_audit.api import create_app
from vibe_audit.domain import RunInput
from vibe_audit.service import Engine
from vibe_audit.store import Store


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("VIBEAUDIT_DATABASE_URL", raising=False)
    app = create_app(data_dir=tmp_path, testing=True)
    with TestClient(app) as value:
        value.headers["X-CSRF-Token"] = value.get(
            "/api/session", headers={"X-VibeAudit-Token": app.state.session_token}
        ).json()["csrf_token"]
        yield value, app


def test_whitebox_findings_are_traceable_and_retests_keep_the_trace(client):
    client, app = client
    engine = app.state.engine
    run = engine.create(RunInput())

    async def finish(identity):
        engine.start(identity)
        await engine.tasks[identity]

    client.portal.call(finish, run["id"])
    parent = app.state.store.get(run["id"])
    finding = next(f for f in parent["findings"] if f["state"] == "hypothesis")
    assert finding["threat_ids"] == ["T-001"]
    response = client.post(f"/api/runs/{run['id']}/retest", json={
        "name": "Patched", "source_path": "", "deployment_id": "fixed",
        "finding_ids": [finding["id"]],
    })
    assert response.status_code == 201, response.text
    assert {c["id"] for c in response.json()["manifest"]["cases"]} == {"C-001", "C-002"}
    client.portal.call(finish, response.json()["id"])
    refreshed = app.state.store.get(run["id"])
    assert next(f for f in refreshed["findings"] if f["id"] == finding["id"])["retests"][-1]["outcome"] == "fail"


@pytest.mark.parametrize("second", ["inconclusive", "blocked", "execution_error", "missing", "uncited", "pass"])
def test_refutation_requires_complete_cited_threat_coverage(client, second):
    client, app = client
    store = app.state.store
    run = app.state.engine.create(RunInput())
    run.update(status="incomplete", threat_model={"threats": [{"id": "T1"}, {"id": "T2"}]},
               cases=[{"id": "C1", "threat_ids": ["T1"]}, {"id": "C2", "threat_ids": ["T2"]}])
    run["findings"] = [{"id": "F1", "state": "hypothesis", "threat_ids": ["T1", "T2"], "evidence_ids": []}]
    cited = []
    for number, status in [(1, "pass"), (2, "pass" if second == "uncited" else second)]:
        if status == "missing":
            continue
        proof = store.put_evidence(run["id"], "blackbox-worker", {"result": {"status": status}})
        run["artifacts"].append(proof)
        run["executions"].append({"id": f"E{number}", "case_id": f"C{number}", "status": status,
                                  "repetition": 0, "evidence_id": proof["id"]})
        if number == 1 or second != "uncited":
            cited.append(proof["id"])
    store.save(run)
    response = client.post(f"/api/runs/{run['id']}/findings/F1/decision", json={
        "decision": "refuted", "rationale": "Check all linked threats", "evidence_ids": cited,
    })
    assert response.status_code == (200 if second == "pass" else 409), response.text
    if second != "pass":
        assert store.get(run["id"])["findings"][0]["state"] == "hypothesis"


def test_untraced_historical_finding_cannot_silently_create_a_retest(client):
    client, app = client
    run = app.state.engine.create(RunInput())
    run.update(status="incomplete", findings=[{"id": "legacy", "threat_ids": [], "evidence_ids": []}])
    app.state.store.save(run)
    response = client.post(f"/api/runs/{run['id']}/retest", json={
        "name": "Patched", "source_path": "", "deployment_id": "fixed", "finding_ids": ["legacy"],
    })
    assert response.status_code == 409
    assert "trace" in response.json()["detail"].lower()


async def test_case_designer_receives_complete_scope_without_credentials(tmp_path, monkeypatch):
    store = Store(tmp_path)
    try:
        engine = Engine(store)
        run = engine.create(RunInput())
        run["mode"] = "live"
        run["manifest"].update(allowed_requests=[{"method": "GET", "path": "/only-approved-route"},
            {"method": "POST", "path": "/ask", "model_body": True, "model_headers": {"Accept": ["application/json"]}}],
            fixture_profile="synthetic-ai-v1", auth_profiles=[{"id": "low", "role": "reader", "model_selectable": True,
            "credential_env": "VIBEAUDIT_TEST_SECRET"}, {"id": "admin", "model_selectable": False}])
        run["threat_model"] = {}
        captured = {}

        async def model(run, profile, instruction, payload, *args, **kwargs):
            captured.update(copy.deepcopy(payload))
            return {"cases": [], "gaps": []}

        monkeypatch.setattr(engine, "model", model)
        monkeypatch.setattr(engine.policy, "case_gate", lambda run: None)
        await engine._case_design(run)
        assert captured["allowed_requests"] == run["manifest"]["allowed_requests"]
        assert captured["fixture_profile"] == "synthetic-ai-v1"
        assert "VIBEAUDIT_TEST_SECRET" not in json.dumps(captured)
        assert "admin" not in json.dumps(captured)
    finally:
        store.close()


def test_snapshot_includes_the_repository_core():
    from pathlib import Path
    from vibe_audit.snapshot import snapshot_source
    package = Path(__file__).resolve().parents[1] / "backend" / "vibe_audit"
    if not package.is_dir():
        pytest.skip("Checkout coverage uses original sources, not mutmut's generated modules")
    source = snapshot_source(str(package))
    files = {f["path"]: f for f in source["files"]}
    assert {"service.py", "worker_entry.py", "worker_runtime.py", "workspace_api.py"} <= files.keys()
    assert "class Engine" in files["service.py"]["content"]


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
async def test_provider_http_error_without_metering_stays_unknown(monkeypatch, status):
    from types import SimpleNamespace
    from vibe_audit import providers

    class GatewayError(Exception):
        status_code = status
        vibeaudit_http_status = status

    async def invoke(*args):
        raise GatewayError()

    monkeypatch.setattr(providers, "_load_litellm", lambda: SimpleNamespace())
    monkeypatch.setattr(providers, "_invoke", invoke)
    profile = {"id": "a", "provider": "openai_compatible", "model_id": "test", "endpoint": "http://127.0.0.1:11434/v1",
               "credential_env": "", "max_output_tokens": 256}
    with pytest.raises(providers.ProviderError) as error:
        await providers.generate_json(profile, "probe", {}, {"data_policy": "local_only",
            "allowed_model_origins": ["http://127.0.0.1:11434"], "max_tokens": 1000})
    assert error.value.usage["tokens_known"] is False


def test_finding_mapping_rejects_unknown_ids_and_records_unmapped_gaps():
    from vibe_audit.contracts import bind_finding_threats
    run = {"findings": [{"id": "F1"}, {"id": "F2"}], "gaps": [], "threat_model": {
        "threats": [{"id": "T1", "finding_ids": ["outside"]}]}}
    with pytest.raises(ValueError, match="outside"):
        bind_finding_threats(run)
    assert all("threat_ids" not in f for f in run["findings"])
    run["threat_model"] = {"threats": [{"id": "T1", "finding_ids": ["F1"]}],
                           "finding_gaps": {"F2": "A dependency scanner issue has no applicable dynamic oracle"}}
    bind_finding_threats(run)
    assert run["findings"][0]["threat_ids"] == ["T1"]
    assert run["findings"][1]["trace_gap"]
    assert run["gaps"] == ["Finding lacks threat traceability: F2"]
    run["threat_model"]["finding_gaps"]["F1"] = "Cannot map it"
    with pytest.raises(ValueError, match="cannot also"):
        bind_finding_threats(run)


def test_retest_coverage_cannot_drop_a_case_or_repetition():
    from vibe_audit.contracts import threat_coverage_outcome
    run = {"cases": [{"id": "C1", "threat_ids": ["T1"], "repetitions": 2}], "executions": [
        {"case_id": "C1", "repetition": 0, "status": "pass"},
        {"case_id": "C1", "repetition": 1, "status": "pass"}]}
    assert threat_coverage_outcome(run, {"T1"}) == "pass"
    assert threat_coverage_outcome(run, {"T1"}, required_case_ids={"C1", "C2"}) == "inconclusive"
    run["executions"][1]["repetition"] = 0
    assert threat_coverage_outcome(run, {"T1"}) == "inconclusive"
    run["executions"].pop()
    assert threat_coverage_outcome(run, {"T1"}) == "inconclusive"


@pytest.mark.parametrize("content", ["", "alpha\nbeta\n" * 2000, "漢字\\\"" * 2000])
def test_source_batches_keep_every_character_and_original_lines(content):
    from vibe_audit.snapshot import review_batches
    source = {"digest": "frozen", "files": [{"path": "large.py", "content": content, "sha256": "raw"},
                                          {"path": "other.py", "content": "second\n", "sha256": "other"}]}
    batches = review_batches(source, 2048)
    assert all(len(json.dumps(b, ensure_ascii=False).encode()) <= 2048 for b in batches)
    for original in source["files"]:
        chunks = [f for batch in batches for f in batch["files"] if f["path"] == original["path"]]
        assert "".join(c["content"] for c in chunks) == original["content"]
        line = 1
        for chunk in chunks:
            assert chunk.get("line_start", 1) == line
            line += chunk["content"].count("\n")
    assert review_batches(source, 1000000) == [source]
    with pytest.raises(ValueError, match="too small"):
        review_batches(source, 20)


def test_review_batch_metadata_and_exact_boundaries_are_stable_for_resume():
    from vibe_audit.domain import digest
    from vibe_audit.snapshot import review_batches
    source = {"digest": "frozen", "files": [
        {"path": "empty.py", "content": "", "sha256": "a", "content_sha256": "A"},
        {"path": "large.py", "content": "line\n" * 200 + "tail漢字", "sha256": "b", "content_sha256": "B"}]}
    original = copy.deepcopy(source)
    plan = review_batches(source, 512)
    assert source == original
    assert all(set(batch) == {"digest", "files"} and batch["digest"] == "frozen" and batch["files"] for batch in plan)
    offset = defaultdict(int)
    for batch in plan:
        for chunk in batch["files"]:
            item = next(f for f in source["files"] if f["path"] == chunk["path"])
            assert chunk["sha256"] == item["sha256"] and chunk["content_sha256"] == item["content_sha256"]
            assert chunk["char_start"] == offset[chunk["path"]]
            offset[chunk["path"]] += len(chunk["content"])
    assert digest(plan) == "a82bcf0db8a959831816400e4d34e74346dc642105259834f06a810deaccb59a"
    assert review_batches(source, len(json.dumps(source, ensure_ascii=False).encode())) == [source]
    small = [{"path": "a", "content": "漢字"}, {"path": "b", "content": ""}]
    packed = {"digest": "x", "files": [{**f, "line_start": 1, "char_start": 0} for f in small]}
    boundary = len(json.dumps(packed, ensure_ascii=False).encode())
    assert review_batches({"digest": "x", "files": small, "gaps": ["x" * 1000]}, boundary) == [packed]
    first = {"path": "a", "content": "", "line_start": 1, "char_start": 0}
    second = {"path": "b" * 100, "content": "", "line_start": 1, "char_start": 0}
    single_limit = len(json.dumps({"digest": "x", "files": [second]}, ensure_ascii=False).encode())
    overflow = {"digest": "x", "files": [{"path": f["path"], "content": ""} for f in (first, second)], "gaps": ["x" * 1000]}
    assert review_batches(overflow, single_limit) == [{"digest": "x", "files": [first]}, {"digest": "x", "files": [second]}]
    minimal = {"digest": "x", "files": [{"path": "a", "content": ""}], "gaps": ["x" * 1000]}
    assert review_batches(minimal, 128)
    for limit in (0, 20, 127):
        with pytest.raises(ValueError, match="^Model batch limit is too small for source metadata$"):
            review_batches(minimal, limit)
    oversized_metadata = {"digest": "x", "files": [{"path": "a" * 2000, "content": ""}]}
    with pytest.raises(ValueError, match="^Model batch limit is too small for source metadata$"):
        review_batches(oversized_metadata, 512)
    assert review_batches({"digest": "x", "files": [], "gaps": ["x" * 1000]}, 512) == []


async def test_each_reviewer_reads_all_batches_and_resume_reuses_paid_batches(tmp_path, monkeypatch):
    import asyncio
    from vibe_audit import providers
    from vibe_audit.domain import digest

    store = Store(tmp_path)
    try:
        engine = Engine(store)
        run = engine.create(RunInput())
        run["mode"] = "live"
        run["source_digest"] = digest("large")
        artifact = store.put_evidence(run["id"], "source-snapshot", {"digest": run["source_digest"],
            "files": [{"path": "large.py", "content": "x = 1\n" * 1800, "sha256": "raw"}]})
        run["artifacts"] = [artifact]
        run["snapshot_id"] = artifact["id"]
        engine.cancel_flags[run["id"]] = asyncio.Event()
        monkeypatch.setattr(providers, "MAX_PAYLOAD_BYTES", 4096)
        seen = defaultdict(list)
        fail = [True]

        async def call(run, profile, instruction, payload, response_contract=None):
            if profile["role"] == "commander":
                return {"reviewer_order": ["reviewer-a", "reviewer-b", "reviewer-c"], "focus": [], "rationale": "Same scope"}
            batch = payload["source"]
            if profile["id"] == "reviewer-a" and len(seen["reviewer-a"]) == 1 and fail[0]:
                fail[0] = False
                raise providers.ProviderError("Model output was truncated", code="truncated")
            seen[profile["id"]].append(batch)
            return {"findings": [], "gaps": []}

        async def scan(run):
            return None

        monkeypatch.setattr(engine, "call_model", call)
        monkeypatch.setattr(engine, "_scan_source", scan)
        with pytest.raises(Exception, match="Incomplete review"):
            await engine._whitebox(run)
        assert len(seen["reviewer-a"]) == 1
        await engine._whitebox(run)
        assert len(run["reviews"]) == 3
        for identity in ("reviewer-a", "reviewer-b", "reviewer-c"):
            assert "".join(f["content"] for batch in seen[identity] for f in batch["files"]) == "x = 1\n" * 1800
            assert run["review_coverage"]["completed"][identity] == list(range(run["review_coverage"]["batches"]))
    finally:
        store.close()


async def test_unknown_provider_usage_retains_reservation_and_blocks_resume(tmp_path, monkeypatch):
    import asyncio
    from vibe_audit import providers
    from vibe_audit.policy import PolicyError
    store = Store(tmp_path)
    try:
        engine = Engine(store)
        run = engine.create(RunInput())
        engine.cancel_flags[run["id"]] = asyncio.Event()
        engine.locks[run["id"]] = asyncio.Lock()

        async def rejected(profile, system, payload, policy):
            await policy["request_hook"]()
            raise providers.ProviderError("Model request failed", code="provider_http_503", usage={"tokens": 0, "tokens_known": False})

        monkeypatch.setattr(providers, "generate_json", rejected)
        with pytest.raises(providers.ProviderError):
            await engine.call_model(run, run["manifest"]["models"][0], "Review", {})
        assert run["usage_unknown"] and run["reserved_tokens"] > 0
        run["status"] = "blocked"
        store.save(run)
        with pytest.raises(PolicyError, match="usage is unknown"):
            engine.start(run["id"], resume=True)
    finally:
        store.close()


def test_validation_provenance_counts_skips_and_binds_source_changes(tmp_path):
    import importlib.util
    import subprocess
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "scripts" / "validation-provenance.py"
    if not path.exists():
        pytest.skip("Provenance CLI is verified in the source checkout")
    spec = importlib.util.spec_from_file_location("validation_provenance", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    xml = tmp_path / "receipt.xml"
    xml.write_text('<testsuites><testsuite tests="4" failures="1" errors="0" skipped="1"><testcase><skipped message="No Docker"/></testcase></testsuite></testsuites>')
    result = module.receipt(xml)
    assert result["successful_records"] == 2 and result["failures"] == 1 and result["skip_reasons"] == ["No Docker"]
    xml.write_text('<!DOCTYPE x><testsuite tests="1"/>')
    with pytest.raises(ValueError, match="declarations"):
        module.receipt(xml)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "backend").mkdir()
    code = tmp_path / "backend" / "core.py"
    code.write_text("a = 1\n")
    before = module.source_inputs(tmp_path)
    code.write_text("a = 2\n")
    assert before.keys() == module.source_inputs(tmp_path).keys()
    assert before["backend/core.py"] != module.source_inputs(tmp_path)["backend/core.py"]


@pytest.mark.parametrize("severity", [None, "low", "critical"])
async def test_dynamic_confirmation_does_not_invent_impact_severity(tmp_path, monkeypatch, severity):
    from vibe_audit.policy import sealed
    store = Store(tmp_path)
    try:
        engine = Engine(store)
        design = engine._case_design

        async def cases(run):
            await design(run)
            for case in run["cases"]:
                case.pop("severity", None)
                if severity is not None:
                    case["severity"] = severity
                case["hash"] = sealed(case)

        monkeypatch.setattr(engine, "_case_design", cases)
        run = engine.create(RunInput())
        engine.start(run["id"])
        await engine.tasks[run["id"]]
        result = store.get(run["id"])
        confirmed = next(f for f in result["findings"] if f["state"] == "validated_dynamic")
        assert confirmed["severity"] == (severity or "unrated")
    finally:
        store.close()


async def test_parallel_review_failure_does_not_erase_unknown_usage_reservation(tmp_path, monkeypatch):
    import asyncio
    from vibe_audit import providers
    from vibe_audit.policy import PolicyError
    store = Store(tmp_path)
    try:
        engine = Engine(store)
        run = engine.create(RunInput())
        run["mode"] = "live"
        run["source_digest"] = "frozen"
        run["commander_plan"] = {"reviewer_order": ["reviewer-a", "reviewer-b", "reviewer-c"], "focus": []}
        snapshot = store.put_evidence(run["id"], "source-snapshot", {"digest": "frozen", "files": []})
        run["artifacts"] = [snapshot]
        run["snapshot_id"] = snapshot["id"]
        engine.cancel_flags[run["id"]] = asyncio.Event()
        engine.locks[run["id"]] = asyncio.Lock()

        async def generate(profile, system, payload, policy):
            await policy["request_hook"]()
            if profile["id"] == "reviewer-a":
                raise providers.ProviderError("Model request failed", code="provider_http_503", usage={"tokens": 0, "tokens_known": False})
            return {"data": {"findings": [], "gaps": []}, "usage": {"tokens": 1, "tokens_known": True}}

        async def scan(run):
            return None

        monkeypatch.setattr(providers, "generate_json", generate)
        monkeypatch.setattr(engine, "_scan_source", scan)
        with pytest.raises(PolicyError):
            await engine._whitebox(run)
        assert run["usage_unknown"] is True
        assert run["reserved_tokens"] > 0
    finally:
        store.close()
