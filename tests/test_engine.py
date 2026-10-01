import asyncio
import copy
import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vibe_audit.api import create_app
from vibe_audit.catalog import default_catalog_root
from vibe_audit.domain import RunInput, digest
from vibe_audit.policy import PolicyError, sealed
from vibe_audit.service import Engine, report_sarif
from vibe_audit.store import Store


@pytest.fixture
def engine(tmp_path):
    store=Store(tmp_path)
    value=Engine(store)
    yield value
    store.close()


async def finished_demo(engine):
    run=engine.create(RunInput(name="Contract demo"))
    engine.start(run["id"])
    await engine.tasks[run["id"]]
    return engine.store.get(run["id"])


async def test_end_to_end_demo_is_honest_and_preserves_minority(engine):
    run=await finished_demo(engine)
    assert run["stage"]=="complete",run.get("error")
    assert run["status"]=="incomplete"
    assert len(run["reviews"])==3
    assert all(r["simulated"] for r in run["reviews"])
    assert [x["status"] for x in run["executions"]]==["fail","pass","inconclusive"]
    assert any("C-003: inconclusive" in gap for gap in run["gaps"])
    assert run["usage"]["model_calls"]==0
    assert run["usage"]["requests"]==3
    assert any(f["agent_ids"]==["reviewer-c"] for f in run["findings"])
    stages=[e["stage"] for e in run["events"]]
    assert stages.index("threat_model")<stages.index("blackbox")
    assert "SYNTHETIC" in run["report_note"]
    assert report_sarif(run)["runs"][0]["results"][0]["properties"]["synthetic"] is True


async def test_sarif_level_follows_evidence_and_keeps_blackbox_findings(engine):
    run=await finished_demo(engine)
    results=report_sarif(run)["runs"][0]["results"]
    assert len(results)==len(run["findings"])
    by_state={r["properties"]["evidenceState"]:r for r in results}
    assert by_state["hypothesis"]["level"]=="note"
    dynamic=by_state["validated_dynamic"]
    assert dynamic["level"]=="error" and dynamic["ruleId"]=="blackbox-observation"
    assert dynamic["locations"][0]["logicalLocations"]==[{"name":"GET /orders/private","kind":"resource"}]
    assert dynamic["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]=="/orders/private"
    refuted=copy.deepcopy(run)
    finding=next(f for f in refuted["findings"] if f["state"]=="validated_dynamic")
    finding.update(state="refuted",counterevidence=["E-pass"])
    result=next(r for r in report_sarif(refuted)["runs"][0]["results"] if r["properties"]["evidenceState"]=="refuted")
    assert result["level"]=="none" and result["suppressions"][0]["kind"]=="external"
    assert "E-pass" in result["suppressions"][0]["justification"]


async def test_catalog_failure_names_the_file(engine,tmp_path,monkeypatch):
    root=tmp_path/"catalog-copy"
    shutil.copytree(default_catalog_root(),root)
    (root/"sources"/"asvs-5.0.0.json").write_bytes(b"{}")
    monkeypatch.setenv("VIBEAUDIT_CATALOG_ROOT",str(root))
    run=await finished_demo(engine)
    assert (run["stage"],run["status"])==("preflight","failed")
    assert run["error"]=="Catalog integrity mismatch: sources/asvs-5.0.0.json"


async def test_missing_model_never_issues_blackbox_capability(engine):
    run=await finished_demo(engine)
    run["reviews"].pop()
    with pytest.raises(PolicyError,match="Three"):
        engine.policy.case_gate(run)
    assert run["id"] not in engine.policy.receipts


@pytest.mark.parametrize("mutation",["missing","stale","fake_standard","broken_asset","missing_oracle","broken_threat"])
async def test_threat_and_case_gate_fail_closed(engine,mutation):
    run=await finished_demo(engine)
    if mutation=="missing": run["threat_model"]=None
    elif mutation=="stale": run["threat_model"]["source_digest"]="old"
    elif mutation=="fake_standard":
        run["threat_model"]["standards"]=["ASVS-FAKE"]
        run["threat_model"]["hash"]=sealed(run["threat_model"])
    elif mutation=="broken_asset":
        run["threat_model"]["dataflows"][0]["target"]="missing"
        run["threat_model"]["hash"]=sealed(run["threat_model"])
    elif mutation=="missing_oracle":
        run["cases"][0]["oracle"]={}
        run["cases"][0]["hash"]=sealed(run["cases"][0])
    elif mutation=="broken_threat":
        run["cases"][0]["threat_ids"]=["T-MISSING"]
        run["cases"][0]["hash"]=sealed(run["cases"][0])
    with pytest.raises(PolicyError): engine.policy.case_gate(run)


async def test_malformed_model_case_still_saves_the_blocked_run(engine,monkeypatch):
    gate=engine.policy.case_gate
    def omit_requirement(run):
        # Model output can leave out any field; the gate must reject it and the save must still succeed.
        del run["cases"][0]["requirement_id"]
        run["cases"][0]["hash"]=sealed(run["cases"][0])
        gate(run)
    monkeypatch.setattr(engine.policy,"case_gate",omit_requirement)
    run=await finished_demo(engine)
    assert (run["stage"],run["status"],run["error"])==("case_design","blocked","Case security requirement mismatch")
    engine.event(engine.runs[run["id"]],"Later event")
    assert engine.store.get(run["id"])["events"][-1]["message"]=="Later event"


async def test_whitebox_resume_keeps_paid_reviews_and_sealed_scans(engine,monkeypatch):
    run=await finished_demo(engine)
    run.update(mode="live",status="running",stage="whitebox",reviews=[],tool_results=[],commander_plan=None)
    manifest=run["manifest"]
    manifest.update(mode="live",static_tools=["semgrep","osv"])
    for profile in manifest["models"]:
        profile.update(provider="openai_compatible",endpoint="http://127.0.0.1:11434/v1")
    run["manifest_hash"]=digest(manifest)
    run.update(staging={"path":"unused"},tool_manifest={"tools":1},runtime_config_hash="h")
    engine.runtime_configs["h"]={}
    monkeypatch.setattr("vibe_audit.staging.verify_staging",lambda staging:True)
    monkeypatch.setattr("vibe_audit.resource_manifest.resource_manifest",lambda config,tools:{"tools":1})
    scans,calls=[],[]
    class Runtime:
        async def run_scanner(self,tool,path,**kwargs):
            scans.append(tool)
            return {"status":"completed","findings":[{"file":"app.py","line":1,"title":tool,"rule_id":tool}],"gaps":[],"limitations":[]}
    monkeypatch.setattr(engine,"runtime",lambda run:Runtime())
    reviewers=[p["id"] for p in manifest["models"] if p["role"]=="reviewer"]
    failing={reviewers[-1]}
    async def model(run,profile,instruction,payload,contract=None):
        calls.append(profile["id"])
        if profile["role"]=="commander":
            return {"reviewer_order":reviewers,"focus":["Billing export"],"rationale":"r"}
        if profile["id"] in failing:
            raise RuntimeError("transient provider failure")
        return {"findings":[],"gaps":[]}
    monkeypatch.setattr(engine,"model",model)
    engine.cancel_flags[run["id"]]=asyncio.Event()
    with pytest.raises(PolicyError,match="Incomplete review"):
        await engine._whitebox(run)
    focus=list(run["commander_plan"]["focus"])
    failing.clear()
    calls.clear()
    await engine._whitebox(run)
    # Only the reviewer that failed is called again; scanner results are not appended twice.
    assert calls==reviewers[-1:]
    assert scans==["semgrep","osv"] and [r["scanner_id"] for r in run["tool_results"]]==["semgrep","osv"]
    assert [r["agent_id"] for r in run["reviews"]]==reviewers and all(r["status"]=="completed" for r in run["reviews"])
    assert run["commander_plan"]["focus"]==focus


async def test_time_budget_counts_active_time_across_resume_and_restart(engine,tmp_path):
    run=await finished_demo(engine)
    budget=run["manifest"]["budget"]["max_seconds"]
    spent=run["active_seconds"]
    assert run["attempt_started_at"] is None and 0<spent<budget
    # The pause before resuming outlasts the whole budget; only the active time counts.
    run["started_at"]="2026-01-01T00:00:00+00:00"
    engine.store.save(run)
    engine.start(run["id"],resume=True)
    await engine.tasks[run["id"]]
    resumed=engine.store.get(run["id"])
    assert (resumed["status"],resumed["error"])==("incomplete",None)
    assert spent<=resumed["active_seconds"]<budget
    # A controller restart charges the interrupted attempt up to its last save.
    resumed.update(status="running",attempt_started_at="2026-01-01T00:00:00+00:00")
    engine.store.save(resumed)
    restarted=Engine(engine.store).store.get(run["id"])
    assert restarted["attempt_started_at"] is None and restarted["active_seconds"]>budget
    with pytest.raises(PolicyError,match="Time budget exhausted"):
        engine.check_active(restarted)
    restarted.update(status="running",stage="blackbox")
    engine.policy.case_gate(restarted)
    with pytest.raises(PolicyError,match="Run time budget exhausted"):
        engine.policy.authorize(restarted,restarted["cases"][0],asyncio.Event())


@pytest.mark.parametrize("outcome",["success","known_failure","unknown_failure"])
async def test_model_call_returns_its_reservation_once_usage_is_counted(engine,monkeypatch,outcome):
    from vibe_audit.providers import ProviderError
    run=engine.create(RunInput(name="Reservation"))
    run["status"]="running"
    engine.cancel_flags[run["id"]]=asyncio.Event()
    engine.locks[run["id"]]=asyncio.Lock()
    async def generate_json(profile,system,payload,policy):
        await policy["request_hook"]()
        assert run["reserved_tokens"]>0
        if outcome=="success":
            return {"data":{"ok":True},"usage":{"tokens":7}}
        raise ProviderError("synthetic",code="endpoint_unavailable",usage={"model_calls":1,"tokens":0,"tokens_known":outcome=="known_failure"})
    monkeypatch.setattr("vibe_audit.providers.generate_json",generate_json)
    profile=run["manifest"]["models"][0]
    if outcome=="success":
        assert await engine.model(run,profile,"Return JSON.",{})=={"ok":True}
    else:
        with pytest.raises(ProviderError):
            await engine.model(run,profile,"Return JSON.",{})
    stored=engine.store.get(run["id"])
    if outcome=="unknown_failure":
        # The provider may have billed the call, so its reservation stays and the latch stops further calls.
        assert stored["usage_unknown"] is True and stored["reserved_tokens"]>0
    else:
        assert stored["reserved_tokens"]==0 and not stored.get("usage_unknown")
        assert stored["usage"]["tokens"]==(7 if outcome=="success" else 0)


async def test_capability_rejects_changed_case_and_manifest(engine):
    run=await finished_demo(engine)
    run.update(status="running",stage="blackbox")
    engine.policy.case_gate(run)
    case=copy.deepcopy(run["cases"][0])
    case["path"]="/different"
    with pytest.raises(PolicyError): engine.policy.authorize(run,case,asyncio.Event())
    run["manifest"]["target_url"]="http://changed.example"
    with pytest.raises(PolicyError): engine.policy.authorize(run,run["cases"][0],asyncio.Event())


async def test_unknown_dispatch_not_replayed_on_resume(engine):
    run=await finished_demo(engine)
    job=engine.store.job(run["id"],run["cases"][0])
    engine.store.update_job(job,"sent",{"side_effects":True})
    with pytest.raises(PolicyError,match="outcome_unknown"):
        engine.start(run["id"],resume=True)


async def test_evidence_corruption_blocks_report(engine):
    run=await finished_demo(engine)
    artifact=run["artifacts"][0]
    path=engine.store.artifacts/artifact["filename"]
    body=json.loads(path.read_text(encoding="utf-8"))
    body["content"]={"fake":True}
    path.write_text(json.dumps(body),encoding="utf-8")
    with pytest.raises(ValueError,match="integrity"):
        engine.store.evidence(artifact,run["id"])


async def test_cancel_prevents_further_requests(engine):
    run=engine.create(RunInput())
    engine.start(run["id"])
    engine.cancel(run["id"])
    await engine.tasks[run["id"]]
    result=engine.store.get(run["id"])
    assert result["status"]=="cancelled"
    assert result["usage"]["requests"]==0


def open_session(client):
    return client.get("/api/session",headers={"X-VibeAudit-Token":client.app.state.session_token})


def test_local_api_session_csrf_origin_host_and_source_boundary(tmp_path):
    with TestClient(create_app(tmp_path,testing=True)) as client:
        assert client.get("/api/runs").status_code==401
        # Any local process reaches loopback: without the startup token it gets no session to probe models with.
        for headers in [{},{"X-VibeAudit-Token":"x"*43},{"X-VibeAudit-Token":client.app.state.session_token+"x"}]:
            response=client.get("/api/session",headers=headers)
            assert response.status_code==401
            assert "set-cookie" not in response.headers
        probe={"profile":{"id":"reviewer-a","role":"reviewer","provider":"openai_compatible","model_id":"m","family":"f","endpoint":"http://127.0.0.1:9/v1","credential_env":"VIBEAUDIT_TEST_KEY"},
               "budget":{"max_model_calls":1,"max_tokens":1000,"max_seconds":10},"data_policy":"local_only"}
        assert client.post("/api/models/probe",json=probe).status_code==401
        response=open_session(client)
        csrf=response.json()["csrf_token"]
        assert "HttpOnly" in response.headers["set-cookie"]
        # The cookie alone resumes the existing session, so reloading the workbench needs no token.
        assert client.get("/api/session").json()["csrf_token"]==csrf
        assert client.post("/api/runs",json={"mode":"demo"}).status_code==403
        headers={"X-CSRF-Token":csrf}
        assert client.post("/api/runs",json={"mode":"demo"},headers={**headers,"Origin":"https://evil.example"}).status_code==403
        assert client.get("/api/session",headers={"Host":"evil.example"}).status_code==403
        assert client.get("/api/session",headers={"Sec-Fetch-Site":"cross-site"}).status_code==403
        response=client.post("/api/runs",json={"mode":"demo","name":"<script>alert(1)</script>"},headers=headers)
        assert response.status_code==201
        assert response.json()["mode"]=="demo"
        assert client.get("/api/runs").json()["runs"]


def test_unconfirmed_worker_cleanup_closes_by_attestation_and_never_resumes(tmp_path):
    store=Store(tmp_path)
    run=Engine(store).create(RunInput(name="Stuck cleanup"))
    run.update(status="running",workers_pending_cleanup=True)
    store.save(run)
    store.close()
    with TestClient(create_app(tmp_path,testing=True)) as client:
        headers={"X-CSRF-Token":open_session(client).json()["csrf_token"]}
        base=f"/api/runs/{run['id']}"
        assert client.get(base).json()["status"]=="cancelling"
        # No task is left to move the run, so the stream ends instead of polling forever.
        assert "event: done" in client.get(base+"/events").text
        assert client.post(base+"/resume",headers=headers).status_code==409
        assert client.post(base+"/reconcile",json={"attestation":""},headers=headers).status_code==422
        response=client.post(base+"/reconcile",json={"attestation":"Removed worker containers by hand"},headers=headers)
        assert response.status_code==200
        reconciled=response.json()
        assert reconciled["status"]=="blocked" and reconciled["workers_pending_cleanup"] is True
        assert any("attested by the local operator" in gap for gap in reconciled["gaps"])
        artifact=reconciled["artifacts"][-1]
        assert artifact["producer"]=="operator-attestation"
        assert client.get(f"{base}/evidence/{artifact['id']}").json()["content"]["attestation"]=="Removed worker containers by hand"
        assert client.post(base+"/reconcile",json={"attestation":"again"},headers=headers).status_code==409
        assert "outcome_unknown" in client.post(base+"/resume",headers=headers).json()["detail"]


async def test_reconcile_waits_for_the_task_and_keeps_an_operator_cancel_cancelled(engine):
    run=engine.create(RunInput(name="Cancelled with cleanup pending"))
    run.update(status="cancelling",workers_pending_cleanup=True)
    engine.store.save(run)
    engine.tasks[run["id"]]=asyncio.get_running_loop().create_future()
    with pytest.raises(PolicyError,match="still executing"):
        engine.reconcile(run["id"],"done")
    engine.tasks[run["id"]].set_result(None)
    assert engine.reconcile(run["id"],"done")["status"]=="cancelled"


@pytest.mark.parametrize("token",["x"*31,"x"*32+" ","x"*32+"#"])
def test_weak_startup_token_is_refused(tmp_path,monkeypatch,token):
    monkeypatch.setenv("VIBEAUDIT_SESSION_TOKEN",token)
    with pytest.raises(ValueError,match="VIBEAUDIT_SESSION_TOKEN"):
        create_app(tmp_path,testing=True)


def test_configured_startup_token_opens_session(tmp_path,monkeypatch):
    monkeypatch.setenv("VIBEAUDIT_SESSION_TOKEN","s"*40)
    with TestClient(create_app(tmp_path,testing=True)) as client:
        assert client.get("/api/session",headers={"X-VibeAudit-Token":"s"*40}).status_code==200


def test_live_requires_diversity_and_no_demo():
    with pytest.raises(ValueError): RunInput(mode="live",source_path=".",target_url="http://127.0.0.1",allowed_target_ips=["127.0.0.1"])


def test_artifact_cannot_be_reassigned_to_other_run(tmp_path):
    store=Store(tmp_path)
    artifact=store.put_evidence("run-a","worker",{"result":"fail"})
    with pytest.raises(ValueError): store.evidence(artifact,"run-b")
    store.close()


def test_chunked_api_body_limit_does_not_trust_content_length(tmp_path):
    with TestClient(create_app(tmp_path,testing=True)) as client:
        csrf=open_session(client).json()["csrf_token"]
        def chunks():
            yield b'{"mode":"demo","notes":"'
            for _ in range(9):
                yield b"x"*(64*1024)
            yield b'"}'
        response=client.post("/api/runs",content=chunks(),headers={
            "X-CSRF-Token":csrf,"Content-Type":"application/json","Transfer-Encoding":"chunked"})
        assert "content-length" not in response.request.headers
        assert response.status_code==413
        assert client.get("/api/runs").json()["runs"]==[]


@pytest.mark.parametrize("length",["not-a-number","-1"])
def test_invalid_content_length_is_rejected_without_creating_run(tmp_path,length):
    with TestClient(create_app(tmp_path,testing=True)) as client:
        csrf=open_session(client).json()["csrf_token"]
        response=client.post("/api/runs",content=b'{"mode":"demo"}',headers={
            "X-CSRF-Token":csrf,"Content-Type":"application/json","Content-Length":length})
        assert response.status_code==400
        assert client.get("/api/runs").json()["runs"]==[]


@pytest.mark.parametrize("fail_at",["run_write","commit"])
def test_finish_job_rolls_back_both_journal_and_run_on_failure(engine,monkeypatch,fail_at):
    """Faults after either write cannot leave a finished job absent from the run."""
    run=engine.create(RunInput())
    case={"id":"atomic-case","hash":"synthetic-hash","side_effects":False}
    job_id=engine.store.job(run["id"],case)
    sent={"case_hash":case["hash"]}
    engine.store.update_job(job_id,"sent",sent)
    execution={"id":job_id,"case_id":case["id"],"status":"pass","repetition":0}
    run["executions"].append(execution)
    execute=engine.store._execute
    def fault(sql,args=()):
        if ((fail_at=="run_write" and sql.startswith("INSERT INTO runs"))
                or (fail_at=="commit" and sql=="COMMIT")):
            raise RuntimeError("Synthetic transaction interruption")
        return execute(sql,args)
    monkeypatch.setattr(engine.store,"_execute",fault)
    with pytest.raises(RuntimeError,match="interruption"):
        engine.store.finish_job(job_id,execution,run)
    # A new connection reads durable state, rather than inspecting local objects.
    reader=Store(engine.store.root)
    try:
        assert reader.get(run["id"])["executions"]==[]
        journal=reader.jobs(run["id"])
        assert journal[0]["status"]=="sent"
        assert journal[0]["payload"]==sent
    finally:
        reader.close()


def test_finish_job_commits_journal_and_execution_together(engine):
    run=engine.create(RunInput())
    case={"id":"atomic-case","hash":"synthetic-hash","side_effects":False}
    job_id=engine.store.job(run["id"],case)
    engine.store.update_job(job_id,"sent",{"case_hash":case["hash"]})
    execution={"id":job_id,"case_id":case["id"],"status":"pass","repetition":0}
    run["executions"].append(execution)
    engine.store.finish_job(job_id,execution,run)
    reader=Store(engine.store.root)
    try:
        assert reader.get(run["id"])["executions"]==[execution]
        assert reader.jobs(run["id"])[0]["status"]=="finished"
        assert reader.jobs(run["id"])[0]["payload"]==execution
    finally:
        reader.close()


async def test_unknown_provider_usage_persists_and_blocks_resume_after_restart(engine,monkeypatch):
    from vibe_audit import providers
    run=engine.create(RunInput())
    run["status"]="running"
    engine.cancel_flags[run["id"]]=asyncio.Event()
    engine.locks[run["id"]]=asyncio.Lock()
    async def unknown_usage(profile,system,payload,policy):
        await policy["request_hook"]()
        raise providers.ProviderError("Synthetic lost response",usage={
            "model_calls":1,"tokens":7,"tokens_known":False})
    monkeypatch.setattr(providers,"generate_json",unknown_usage)
    with pytest.raises(providers.ProviderError):
        await engine.model(run,run["manifest"]["models"][0],"Synthetic metering exercise",{})
    reader=Store(engine.store.root)
    try:
        restarted=Engine(reader)
        persisted=reader.get(run["id"])
        assert persisted["usage_unknown"] is True
        assert persisted["usage"]["tokens_known"] is False
        assert persisted["usage"]["tokens"]==7
        assert persisted["usage"]["model_calls"]==1
        assert persisted["status"]=="incomplete"
        with pytest.raises(PolicyError,match="usage is unknown"):
            restarted.start(run["id"],resume=True)
        assert not restarted.tasks
        assert reader.get(run["id"])["status"]=="incomplete"
    finally:
        reader.close()


@pytest.mark.parametrize("control_permission",[None,"POST","GET"])
async def test_positive_control_needs_exact_scope_and_sealed_case_authorization(engine,monkeypatch,control_permission):
    """Exercise service→adapter→policy with synthetic HTTP, never a real target."""
    from vibe_audit import adapters
    run=await finished_demo(engine)
    run.update(mode="live",status="running",stage="blackbox",executions=[])
    manifest=run["manifest"]
    manifest.update(mode="live",target_url="http://127.0.0.1:11435",allowed_target_ips=["127.0.0.1"])
    for profile in manifest["models"]:
        profile.update(provider="openai_compatible",endpoint="http://127.0.0.1:11434/v1")
    for review in run["reviews"]:
        review.update(provider="openai_compatible",simulated=False)
    manifest["allowed_requests"]=[{"method":"GET","path":"/orders/private"},
                                  {"method":"GET","path":"/allowed-but-not-a-case-step"}]
    if control_permission:
        manifest["allowed_requests"].append({"method":control_permission,"path":"/fixture-private"})
    run["manifest_hash"]=digest(manifest)
    run["threat_model"]["threats"]=run["threat_model"]["threats"][:1]
    run["threat_model"]["requirements"]=run["threat_model"]["requirements"][:1]
    run["threat_model"]["hash"]=sealed(run["threat_model"])
    case=copy.deepcopy(run["cases"][0])
    case.update(adapter="http",threat_model_hash=run["threat_model"]["hash"],preconditions=[{
        "name":"fixture_ready","method":"GET","path":"/fixture-private", "expected_status":200,
        "required_text":["B-PRIVATE-CANARY"]}])
    case["hash"]=sealed(case)
    run["cases"]=[case]
    run["usage"]["requests"]=0
    dispatched=[]
    def synthetic_request(scheme,host,port,pinned,method,path,*rest):
        dispatched.append((method,path))
        return {"complete":True,"status_code":200 if path=="/fixture-private" else 403,
                "body":"B-PRIVATE-CANARY" if path=="/fixture-private" else "Forbidden"}
    monkeypatch.setattr(adapters,"_request",synthetic_request)
    monkeypatch.setattr(adapters,"_pinned_address",lambda *args:"127.0.0.1")
    class ContractRuntime:
        async def run_case(self,manifest,case,**kwargs):
            kwargs.pop("repetition",None)
            kwargs.pop("lease_hook",None)
            return await adapters.execute_case(manifest,case,**kwargs)
    monkeypatch.setattr(engine,"runtime",lambda _:ContractRuntime())
    if control_permission=="GET":
        await engine._blackbox(run)
        assert dispatched==[("GET","/fixture-private"),("GET","/orders/private")]
        assert run["executions"][0]["status"]=="pass"
        assert run["usage"]["requests"]==2
    else:
        with pytest.raises(PolicyError,match="scope"):
            await engine._blackbox(run)
        assert dispatched==[]
        assert run["executions"]==[]
        assert run["usage"]["requests"]==0
        return
    used=run["usage"]["requests"]
    with pytest.raises(PolicyError,match="sealed test case"):
        engine.policy.authorize(run,case,engine.cancel_flags[run["id"]],method="GET",path="/allowed-but-not-a-case-step")
    assert run["usage"]["requests"]==used


async def live_post_case(engine,*,adapter,provenance):
    """Turn a finished demo into a live blackbox stage holding one POST case."""
    run=await finished_demo(engine)
    run.update(mode="live",status="running",stage="blackbox",executions=[])
    manifest=run["manifest"]
    manifest.update(mode="live",target_url="http://127.0.0.1:11435",allowed_target_ips=["127.0.0.1"],
                    allowed_requests=[{"method":"POST","path":"/orders/private"}])
    for profile in manifest["models"]:
        profile.update(provider="openai_compatible",endpoint="http://127.0.0.1:11434/v1")
    for review in run["reviews"]:
        review.update(provider="openai_compatible",simulated=False)
    run["threat_model"]["threats"]=run["threat_model"]["threats"][:1]
    run["threat_model"]["requirements"]=run["threat_model"]["requirements"][:1]
    run["threat_model"]["hash"]=sealed(run["threat_model"])
    case=copy.deepcopy(run["cases"][0])
    case.update(adapter=adapter,method="POST",body={},preconditions=[],side_effects=False,threat_model_hash=run["threat_model"]["hash"])
    if provenance!="operator":
        case["designed_by"]="model"
    # A retest copies the parent's sealed cases, model-designed ones included, into its manifest.
    manifest["cases"]=[] if provenance=="model" else [{k:v for k,v in case.items() if k!="hash"}]
    run["manifest_hash"]=digest(manifest)
    case["hash"]=sealed(case)
    run["cases"]=[case]
    run["usage"]["requests"]=0
    return run


@pytest.mark.parametrize("provenance",["model","retest","operator"])
async def test_model_designed_post_cannot_declare_itself_read_only(engine,monkeypatch,provenance):
    from vibe_audit import adapters
    run=await live_post_case(engine,adapter="http",provenance=provenance)
    dispatched=[]
    def synthetic_request(scheme,host,port,pinned,method,path,*rest):
        dispatched.append((method,path))
        return {"complete":True,"status_code":403,"body":"Forbidden"}
    monkeypatch.setattr(adapters,"_request",synthetic_request)
    monkeypatch.setattr(adapters,"_pinned_address",lambda *args:"127.0.0.1")
    class ContractRuntime:
        async def run_case(self,manifest,case,**kwargs):
            kwargs.pop("repetition",None)
            kwargs.pop("lease_hook",None)
            return await adapters.execute_case(manifest,case,**kwargs)
    monkeypatch.setattr(engine,"runtime",lambda _:ContractRuntime())
    await engine._blackbox(run)
    if provenance=="operator":
        assert dispatched==[("POST","/orders/private")]
    else:
        assert dispatched==[]
        assert run["executions"][0]["status"]=="blocked"
        assert run["usage"]["requests"]==0


@pytest.mark.parametrize("provenance",["model","operator"])
async def test_tool_adapter_cannot_bypass_side_effect_gate(engine,monkeypatch,provenance):
    run=await live_post_case(engine,adapter="schemathesis",provenance=provenance)
    dispatched=[]
    class ToolRuntime:
        async def execute_tool(self,spec,**kwargs):
            dispatched.append(spec["tool_id"])
            return {"status":"execution_error","reason":"synthetic tool","cleanup_confirmed":True}
    monkeypatch.setattr(engine,"runtime",lambda _:ToolRuntime())
    await engine._blackbox(run)
    if provenance=="operator":
        assert dispatched==["schemathesis"]
    else:
        assert dispatched==[]
        assert run["executions"][0]["status"]=="blocked"
        assert "reset/cleanup fixture" in run["executions"][0]["reason"]
