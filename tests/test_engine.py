import asyncio
import copy
import json
import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vibe_audit.api import create_app
from vibe_audit.catalog import default_catalog_root
from vibe_audit.domain import RunInput, digest
from vibe_audit.policy import PolicyError, sealed
from vibe_audit.service import Engine, report_markdown, report_sarif
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
    # Lockfile and location-less findings are reported, and a scanner's rule ID names its result.
    extra=copy.deepcopy(run)
    extra["findings"]+=[{**finding,"id":"osv","state":"corroborated_static","file":"package-lock.json","line":None,"rule_id":"GHSA-xxxx","evidence_ids":[]},
                        {**finding,"id":"loose","state":"hypothesis","file":None,"line":None,"cwe":None,"evidence_ids":[]}]
    assert len(report_sarif(extra)["runs"][0]["results"])==len(extra["findings"])
    osv=[r for r in report_sarif(extra)["runs"][0]["results"] if r["ruleId"]=="GHSA-xxxx"][0]
    assert osv["locations"][0]["physicalLocation"]=={"artifactLocation":{"uri":"package-lock.json"}}
    loose=[r for r in report_sarif(extra)["runs"][0]["results"] if "logicalLocations" in r["locations"][0] and "physicalLocation" not in r["locations"][0]]
    assert loose and loose[0]["ruleId"]=="security-hypothesis"


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


async def test_one_unverifiable_citation_does_not_void_a_review(engine,monkeypatch):
    run=await finished_demo(engine)
    run.update(mode="live",status="running",stage="whitebox",reviews=[],tool_results=[],commander_plan=None)
    manifest=run["manifest"]
    manifest.update(mode="live",static_tools=[])
    for profile in manifest["models"]:
        profile.update(provider="openai_compatible",endpoint="http://127.0.0.1:11434/v1")
    run["manifest_hash"]=digest(manifest)
    run.update(staging={"path":"unused"},tool_manifest={"tools":0},runtime_config_hash="h")
    engine.runtime_configs["h"]={}
    monkeypatch.setattr("vibe_audit.staging.verify_staging",lambda staging:True)
    monkeypatch.setattr("vibe_audit.resource_manifest.resource_manifest",lambda config,tools:{"tools":0})
    monkeypatch.setattr(engine,"runtime",lambda run:object())
    good={"file":"synthetic/orders.py","line":1,"quote":"Synthetic fixture only"}
    reviewers=[p["id"] for p in manifest["models"] if p["role"]=="reviewer"]
    async def model(run,profile,instruction,payload,contract=None):
        if profile["role"]=="commander":
            return {"reviewer_order":reviewers,"focus":[],"rationale":"r"}
        return {"findings":[
            {"title":"Cited correctly","severity":"high","description":"d","source_refs":[good]},
            {"title":"Misquoted","severity":"high","description":"d","source_refs":[good,{**good,"quote":"Synthetic  fixture only"}]},
            {"title":"Too short","severity":"low","description":"d","source_refs":[{**good,"quote":"e"}]},
            {"title":"Elsewhere","severity":"low","description":"d","file":"missing.py","line":3}],"gaps":[]}
    monkeypatch.setattr(engine,"model",model)
    engine.cancel_flags[run["id"]]=asyncio.Event()
    await engine._whitebox(run)
    review=run["reviews"][0]
    assert review["status"]=="completed" and [f["title"] for f in review["findings"]]==["Cited correctly","Misquoted","Too short","Elsewhere"]
    assert [len(f["source_refs"]) for f in review["findings"]]==[1,1,0,0]
    assert review["findings"][3]["file"] is None
    assert sum("dropped 1 source reference" in gap for gap in review["gaps"])==2 and any("outside the frozen source" in gap for gap in review["gaps"])


async def test_oversized_model_payload_keeps_cited_files_or_blocks(engine,monkeypatch):
    from vibe_audit import providers
    run=await finished_demo(engine)
    cited={"path":"synthetic/orders.py","content":"x"*400}
    other={"path":"vendor/big.js","content":"y"*4000}
    monkeypatch.setattr(engine,"source",lambda run:{"digest":"d","files":[cited,other]})
    monkeypatch.setattr(providers,"MAX_PAYLOAD_BYTES",100000)
    assert engine.fitted_source(run,{"candidates":[]},"Challenger")["files"]==[cited,other]
    # Past the limit only the files findings cite keep their text, and the omission is a recorded gap.
    monkeypatch.setattr(providers,"MAX_PAYLOAD_BYTES",3000)
    fitted=engine.fitted_source(run,{"candidates":[]},"Challenger")
    assert [f["content"] for f in fitted["files"]]==[cited["content"],""] and fitted["files"][1]["omitted"]
    assert any(gap.startswith("Challenger received full text only") for gap in run["gaps"])
    monkeypatch.setattr(providers,"MAX_PAYLOAD_BYTES",200)
    with pytest.raises(PolicyError,match="payload limit"):
        engine.fitted_source(run,{"candidates":[]},"Challenger")


async def test_provided_cases_leave_uncovered_threats_as_gaps(engine):
    run=await finished_demo(engine)
    case=next(c for c in run["cases"] if c["id"]=="C-001")
    run["cases"]=[case]
    # Model-designed cases must cover every automated threat.
    with pytest.raises(PolicyError,match="Automated threats without cases"):
        engine.policy.case_gate(run)
    # Cases the operator (or a retest's parent) supplied are the chosen scope; the rest is a visible gap.
    run["manifest"]["cases"]=[{k:v for k,v in case.items() if k!="hash"}]
    run["manifest_hash"]=digest(run["manifest"])
    engine.policy.case_gate(run)
    engine.policy.case_gate(run)
    assert [g for g in run["gaps"] if "without a provided case" in g]==["Automated threats without a provided case were not tested: T-002"]


async def test_threat_model_that_drops_a_provided_case_threat_blocks_early(engine,monkeypatch):
    run=await finished_demo(engine)
    proposal={k:v for k,v in run["threat_model"].items() if k not in {"hash","source_digest","deployment_id"}}
    run.update(mode="live",status="running",stage="threat_model")
    case={k:v for k,v in run["cases"][0].items() if k!="hash"}
    run["manifest"].update(mode="live",cases=[{**case,"threat_ids":["T-RENAMED"]}])
    run["manifest_hash"]=digest(run["manifest"])
    async def model(run,profile,instruction,payload,contract=None):
        return proposal
    monkeypatch.setattr(engine,"model",model)
    monkeypatch.setattr(engine,"fitted_source",lambda run,payload,label:{"files":[]})
    with pytest.raises(PolicyError,match="T-RENAMED"):
        await engine._threat_model(run)


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


def authorize(client):
    """Open a session and send its CSRF token on every later request, as the workbench does."""
    csrf=open_session(client).json()["csrf_token"]
    client.headers["X-CSRF-Token"]=csrf
    return csrf


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
        headers={"X-CSRF-Token":csrf}
        # Cookies reach every port on this host. The cookie alone must not yield the CSRF token or any data.
        response=client.get("/api/session")
        assert response.status_code==401 and "csrf_token" not in response.json()
        assert client.get("/api/session",headers={"X-CSRF-Token":"x"*43}).status_code==401
        for path in ["/api/runs","/api/projects","/api/openapi.json"]:
            response=client.get(path)
            assert response.status_code==403
            assert response.headers["content-security-policy"].startswith("default-src 'self'")
        # A reloaded workbench proves the session with the CSRF token it stored.
        assert client.get("/api/session",headers=headers).json()["csrf_token"]==csrf
        assert client.post("/api/runs",json={"mode":"demo"}).status_code==403
        assert client.post("/api/runs",json={"mode":"demo"},headers={**headers,"Origin":"https://evil.example"}).status_code==403
        assert client.get("/api/session",headers={"Host":"evil.example"}).status_code==403
        assert client.get("/api/session",headers={"Sec-Fetch-Site":"cross-site"}).status_code==403
        response=client.post("/api/runs",json={"mode":"demo","name":"<script>alert(1)</script>"},headers=headers)
        assert response.status_code==201
        assert response.json()["mode"]=="demo"
        assert client.get("/api/runs",headers=headers).json()["runs"]
        for path in ["/api","/api/nope","/api/runs/x/nope","/api/docs"]:
            response=client.get(path,headers=headers)
            assert (response.status_code,response.headers["content-type"])==(404,"application/json")
        assert client.get("/api/openapi.json",headers=headers).json()["info"]["title"]=="Vibe Audit"
        assert "redoc" not in client.get("/redoc").text.lower()
        # A new startup-token exchange replaces this browser's session instead of adding to it.
        renewed=open_session(client).json()["csrf_token"]
        assert renewed!=csrf
        assert client.get("/api/runs",headers=headers).status_code==403
        assert client.get("/api/runs",headers={"X-CSRF-Token":renewed}).status_code==200


def test_unconfirmed_worker_cleanup_closes_by_attestation_and_never_resumes(tmp_path,monkeypatch):
    monkeypatch.delenv("VIBEAUDIT_DATABASE_URL",raising=False)
    store=Store(tmp_path)
    run=Engine(store).create(RunInput(name="Stuck cleanup"))
    run.update(status="running",workers_pending_cleanup=True)
    store.save(run)
    store.close()
    with TestClient(create_app(tmp_path,testing=True)) as client:
        headers={"X-CSRF-Token":authorize(client)}
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


def test_api_errors_stay_structured_instead_of_500(tmp_path,monkeypatch):
    config=tmp_path/"runtime.json"
    # A lease database that refuses connections must not turn the inventory into a server error.
    config.write_text(json.dumps({"profiles":{"default":{"work_root":str(tmp_path/"w"),"backend":"docker","database_url":"postgresql://nobody@127.0.0.1:1/none?connect_timeout=1"}}}))
    monkeypatch.setenv("VIBEAUDIT_RUNTIME_CONFIG",str(config))
    with TestClient(create_app(tmp_path,testing=True),raise_server_exceptions=False) as client:
        authorize(client)
        response=client.get("/api/capabilities")
        assert response.status_code==200 and response.json()["runtime"]["available"] is False
        for body in [b"[]",b'"x"',b"not json",b'{"profile":{}}']:
            response=client.post("/api/models/probe",content=body,headers={"Content-Type":"application/json"})
            assert response.status_code==422 and "detail" in response.json(),body
        run=client.post("/api/runs",json={"mode":"demo"}).json()
        # A retest of an assessment that never ran is refused, by either route.
        assert client.post("/api/runs",json={"mode":"demo","parent_run_id":run["id"]}).status_code==409
        assert client.post(f"/api/runs/{run['id']}/retest",json={"name":"r","source_path":"","deployment_id":"d","finding_ids":["x"]}).status_code==409
        client.post(f"/api/runs/{run['id']}/start")
        for _ in range(100):
            current=client.get(f"/api/runs/{run['id']}").json()
            if current["status"] not in {"created","running"}:break
            time.sleep(.05)
        artifact=current["artifacts"][0]
        (tmp_path/"artifacts"/artifact["filename"]).unlink()
        response=client.get(f"/api/runs/{run['id']}/evidence/{artifact['id']}")
        assert response.status_code==409 and response.json()["detail"]=="Evidence integrity check failed"
        assert client.get("/api/runs/no-such-run").status_code==404


@pytest.mark.parametrize("token",["x"*31,"x"*32+" ","x"*32+"#"])
def test_weak_startup_token_is_refused(tmp_path,monkeypatch,token):
    monkeypatch.setenv("VIBEAUDIT_SESSION_TOKEN",token)
    with pytest.raises(ValueError,match="VIBEAUDIT_SESSION_TOKEN"):
        create_app(tmp_path,testing=True)


def test_configured_startup_token_opens_session(tmp_path,monkeypatch):
    monkeypatch.setenv("VIBEAUDIT_SESSION_TOKEN","s"*40)
    with TestClient(create_app(tmp_path,testing=True)) as client:
        assert client.get("/api/session",headers={"X-VibeAudit-Token":"s"*40}).status_code==200


def test_restart_records_a_sent_request_as_outcome_unknown(tmp_path):
    store=Store(tmp_path)
    run=Engine(store).create(RunInput(name="Crash after dispatch"))
    run.update(status="running",stage="blackbox",cases=[{"id":"C-001","title":"Tenant boundary","hash":"sealed"}])
    store.save(run)
    job=store.job(run["id"],run["cases"][0])
    store.update_job(job,"sent",{"case_hash":"sealed","side_effects":False,"sent_at":"2026-10-03T00:00:00+00:00","repetition":0})
    restarted=Engine(store)
    stored=store.get(run["id"])
    # The dispatch may have reached the target: every export must show it, and nothing may replay it.
    assert stored["status"]=="incomplete" and "after a request was sent" in stored["error"]
    assert [(e["id"],e["case_id"],e["status"],e["repetition"]) for e in stored["executions"]]==[(job,"C-001","outcome_unknown",0)]
    assert any("Tenant boundary" in gap and "never recorded" in gap for gap in stored["gaps"])
    assert [j["status"] for j in store.jobs(run["id"])]==["finished"]
    markdown=report_markdown(stored)
    assert "C-001: outcome\\_unknown" in markdown and "Error: Controller restarted after a request was sent" in markdown
    with pytest.raises(PolicyError,match="outcome_unknown"):
        restarted.start(run["id"],resume=True)
    store.close()


async def test_failure_after_dispatch_leaves_no_silent_sent_job(engine,monkeypatch):
    run=engine.create(RunInput(name="Bug after dispatch"))
    async def crashing_blackbox(run):
        case=run["cases"][0]
        job=engine.store.job(run["id"],case)
        engine.store.update_job(job,"sent",{"case_hash":case["hash"],"side_effects":False,"sent_at":"now","repetition":0})
        raise KeyError("title")
    monkeypatch.setattr(engine,"_blackbox",crashing_blackbox)
    engine.start(run["id"])
    await engine.tasks[run["id"]]
    stored=engine.store.get(run["id"])
    assert stored["status"]=="failed"
    assert [e["status"] for e in stored["executions"]]==["outcome_unknown"]
    with pytest.raises(PolicyError,match="outcome_unknown"):
        engine.start(run["id"],resume=True)


@pytest.mark.parametrize("change",[{"title":None},{"repetitions":"5"},{"headers":["X-Tenant: b"]},{"oracle":{"kind":"deny_sensitive"}},{"preconditions":[{"name":"p","path":"/x"}]}])
def test_malformed_operator_case_is_rejected_before_any_stage(change):
    case=json.loads(Path(__file__).resolve().parents[1].joinpath("fixtures/web-api/bola-case.json").read_text())
    RunInput(cases=[case])
    case.update(change)
    if change.get("title",0) is None:
        del case["title"]
    with pytest.raises(ValueError):
        RunInput(cases=[case])


def test_model_designed_cases_follow_a_strict_contract():
    from vibe_audit.contracts import CaseDesignProposal
    case=json.loads(Path(__file__).resolve().parents[1].joinpath("fixtures/web-api/bola-case.json").read_text())
    assert CaseDesignProposal.model_validate({"cases":[case]}).cases[0].title==case["title"]
    # A model cannot pick a tool adapter, an unsafe control or keys of its own.
    for change in [{"adapter":"zap"},{"preconditions":[{**case["preconditions"][0],"method":"POST"}]},{"designed_by":"operator"},{"method":"DELETE"}]:
        with pytest.raises(ValueError):
            CaseDesignProposal.model_validate({"cases":[{**case,**change}]})


async def test_invalid_unicode_escapes_from_untrusted_json_never_stop_saving(engine):
    run=await finished_demo(engine)
    lone=json.loads('"leak \\ud800 title"')
    run["findings"][0]["title"]=lone
    engine.store.save(run)
    assert engine.store.get(run["id"])["findings"][0]["title"]=="leak \ufffd title"
    artifact=engine.store.put_evidence(run["id"],"blackbox-worker",{"result":{"status":"fail","reason":lone}})
    assert engine.store.evidence(artifact,run["id"])["content"]["result"]["reason"]=="leak \ufffd title"


async def test_trace_marks_the_current_version_of_each_entity(engine):
    run=await finished_demo(engine)
    finding=next(f for f in run["findings"] if f["state"]=="hypothesis")
    finding["state"]="inconclusive"
    engine.store.save(run)
    versions=[e for e in engine.store.trace(run["id"])["entities"] if e["kind"]=="finding" and e["id"]==finding["id"]]
    assert [(e["current"],e["value"]["state"]) for e in versions]==[(True,"inconclusive"),(False,"hypothesis")]


def test_live_requires_diversity_and_no_demo():
    with pytest.raises(ValueError): RunInput(mode="live",source_path=".",target_url="http://127.0.0.1",allowed_target_ips=["127.0.0.1"])


def test_artifact_cannot_be_reassigned_to_other_run(tmp_path):
    store=Store(tmp_path)
    artifact=store.put_evidence("run-a","worker",{"result":"fail"})
    with pytest.raises(ValueError): store.evidence(artifact,"run-b")
    store.close()


def test_chunked_api_body_limit_does_not_trust_content_length(tmp_path,monkeypatch):
    monkeypatch.delenv("VIBEAUDIT_DATABASE_URL",raising=False)
    with TestClient(create_app(tmp_path,testing=True)) as client:
        csrf=authorize(client)
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
def test_invalid_content_length_is_rejected_without_creating_run(tmp_path,monkeypatch,length):
    monkeypatch.delenv("VIBEAUDIT_DATABASE_URL",raising=False)
    with TestClient(create_app(tmp_path,testing=True)) as client:
        csrf=authorize(client)
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


def as_get_case(run,headers=None):
    """Make the live POST case a read-only GET, with optional case headers, and reseal it."""
    run["manifest"]["allowed_requests"]=[{"method":"GET","path":"/orders/private"}]
    case=run["cases"][0]
    case.update(method="GET",body=None,headers=headers or {})
    for item in run["manifest"]["cases"]:
        item.update(method="GET",body=None,headers=headers or {})
    run["manifest_hash"]=digest(run["manifest"])
    case["hash"]=sealed(case)
    return case


@pytest.mark.parametrize("provenance,headers,allowed",[
    ("operator",{"X-HTTP-Method-Override":"DELETE"},False),
    ("operator",{"X-Original-URL":"/admin/users/1"},False),
    ("operator",{"X-Vibe-Identity":"admin"},False),
    ("model",{"X-Tenant":"tenant-b"},False),
    ("operator",{"X-Tenant":"tenant-b"},True),
    ("model",{"Accept":"application/json"},True),
])
async def test_case_headers_cannot_override_method_path_or_relay(engine,monkeypatch,provenance,headers,allowed):
    run=await live_post_case(engine,adapter="http",provenance=provenance)
    as_get_case(run,headers)
    dispatched=[]
    class Runtime:
        async def run_case(self,manifest,case,**kwargs):
            dispatched.append(case["headers"])
            return {"status":"pass","reason":"synthetic","observations":[],"evidence":[],"cleanup_confirmed":True}
    monkeypatch.setattr(engine,"runtime",lambda _:Runtime())
    if allowed:
        await engine._blackbox(run)
        assert dispatched==[headers]
    else:
        with pytest.raises(PolicyError,match="method/path overrides"):
            await engine._blackbox(run)
        assert dispatched==[] and run["executions"]==[]


async def test_violation_with_unconfirmed_target_state_stops_and_never_resumes(engine,monkeypatch):
    run=await live_post_case(engine,adapter="http",provenance="operator")
    as_get_case(run)
    class Runtime:
        async def run_case(self,manifest,case,**kwargs):
            return {"status":"fail","reason":"A forbidden test canary was observed in the response.","observations":[],"evidence":[],
                    "cleanup_confirmed":True,"target_state_confirmed":False}
    monkeypatch.setattr(engine,"runtime",lambda _:Runtime())
    with pytest.raises(PolicyError,match="outcome is unknown"):
        await engine._blackbox(run)
    # The observed violation is kept as a finding even though the target could not be reset.
    assert run["executions"][0]["status"]=="fail"
    assert any(f["state"]=="validated_dynamic" for f in run["findings"])
    run["status"]="blocked"
    engine.store.save(run)
    with pytest.raises(PolicyError,match="outcome_unknown"):
        engine.start(run["id"],resume=True)


async def test_changed_deployment_stops_the_run_and_never_resumes(engine,monkeypatch):
    run=await live_post_case(engine,adapter="http",provenance="operator")
    as_get_case(run)
    run["cases"].append({**run["cases"][0],"id":"C-later"})
    run["cases"][1]["hash"]=sealed(run["cases"][1])
    calls=[]
    class Runtime:
        async def run_case(self,manifest,case,**kwargs):
            calls.append(case["id"])
            return {"status":"blocked","reason":"Deployment identity changed or was not present","observations":[],"evidence":[],
                    "cleanup_confirmed":True,"deployment_changed":True}
    monkeypatch.setattr(engine,"runtime",lambda _:Runtime())
    with pytest.raises(PolicyError,match="deployment identity"):
        await engine._blackbox(run)
    # Nothing else is sent to a deployment other than the declared one.
    assert calls==[run["cases"][0]["id"]] and run["deployment_changed"] is True
    run["status"]="blocked"
    engine.store.save(run)
    with pytest.raises(PolicyError,match="deployment identity changed"):
        engine.start(run["id"],resume=True)


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
