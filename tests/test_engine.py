import asyncio
import copy
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vibe_audit.api import create_app
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


def test_local_api_session_csrf_origin_host_and_source_boundary(tmp_path):
    with TestClient(create_app(tmp_path,testing=True)) as client:
        assert client.get("/api/runs").status_code==401
        response=client.get("/api/session")
        csrf=response.json()["csrf_token"]
        assert "HttpOnly" in response.headers["set-cookie"]
        assert client.post("/api/runs",json={"mode":"demo"}).status_code==403
        headers={"X-CSRF-Token":csrf}
        assert client.post("/api/runs",json={"mode":"demo"},headers={**headers,"Origin":"https://evil.example"}).status_code==403
        assert client.get("/api/session",headers={"Host":"evil.example"}).status_code==403
        assert client.get("/api/session",headers={"Sec-Fetch-Site":"cross-site"}).status_code==403
        response=client.post("/api/runs",json={"mode":"demo","name":"<script>alert(1)</script>"},headers=headers)
        assert response.status_code==201
        assert response.json()["mode"]=="demo"
        assert client.get("/api/runs").json()["runs"]


def test_live_requires_diversity_and_no_demo():
    with pytest.raises(ValueError): RunInput(mode="live",source_path=".",target_url="http://127.0.0.1",allowed_target_ips=["127.0.0.1"])


def test_artifact_cannot_be_reassigned_to_other_run(tmp_path):
    store=Store(tmp_path)
    artifact=store.put_evidence("run-a","worker",{"result":"fail"})
    with pytest.raises(ValueError): store.evidence(artifact,"run-b")
    store.close()


def test_chunked_api_body_limit_does_not_trust_content_length(tmp_path):
    with TestClient(create_app(tmp_path,testing=True)) as client:
        csrf=client.get("/api/session").json()["csrf_token"]
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
        csrf=client.get("/api/session").json()["csrf_token"]
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
