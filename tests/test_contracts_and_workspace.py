import asyncio
import copy
import json
import os
from pathlib import Path
import uuid

import pytest
from fastapi.testclient import TestClient

from vibe_audit.api import create_app
from vibe_audit.contracts import ChallengeItem, complete_requirements, verify_source_references
from vibe_audit.domain import RunInput
from vibe_audit.policy import PolicyError, sealed
from vibe_audit.service import Engine
from vibe_audit.staging import discard_staging, stage_source, verify_staging
from vibe_audit.store import Store


@pytest.fixture(autouse=True)
def private_store(monkeypatch):
    # create_app falls back to this variable, and integration runs point it at the shared test database.
    monkeypatch.delenv("VIBEAUDIT_DATABASE_URL",raising=False)


async def demo(store):
    engine=Engine(store)
    run=engine.create(RunInput(name="Contract and graph integration"))
    engine.start(run["id"])
    await engine.tasks[run["id"]]
    result=store.get(run["id"])
    assert result["stage"]=="complete",result.get("error")
    return engine,result


def test_source_claims_need_exact_frozen_evidence():
    source={"files":[{"path":"app.py","content":"def load():\n    return tenant_id\n"}]}
    verify_source_references([{"file":"app.py","line":2,"quote":"return tenant_id"}],source)
    for ref in ({"file":"other.py","line":2,"quote":"return tenant_id"},
                {"file":"app.py","line":1,"quote":"return tenant_id"},
                {"file":"../app.py","line":2,"quote":"return tenant_id"},
                # A couple of characters occur on almost any line and locate nothing.
                {"file":"app.py","line":2,"quote":"t"},{"file":"app.py","line":2,"quote":"ret  "}):
        with pytest.raises(ValueError):
            verify_source_references([ref],source)


def test_a_challenge_must_carry_evidence_content():
    """An empty challenge would inflate the record without saying anything."""
    assert ChallengeItem(finding_id="F-1",counterevidence="The sealing hash already covers this file.").counterevidence
    assert ChallengeItem(finding_id="F-1",missing_evidence="No control execution was recorded.").missing_evidence
    for empty in [{}, {"counterevidence":"   "}, {"missing_evidence":""}]:
        with pytest.raises(ValueError):
            ChallengeItem(finding_id="F-1",**empty)


def test_model_cannot_claim_operator_requirements_or_change_supplied_rules():
    model={"requirements":[{"id":"R1","statement":"tenant isolation","threat_ids":[],"source_kind":"operator","source":"model assertion","standard_ids":[]}],
           "threats":[{"id":"T1","requirement_id":"R1","invariant":"tenant isolation"}]}
    result=complete_requirements(model,[])
    assert result[0]["source_kind"]=="derived"
    assert result[0]["threat_ids"]==["T1"]
    with pytest.raises(ValueError,match="changed"):
        complete_requirements(model,[{"id":"R1","statement":"a different operator policy","source":"owner","source_kind":"operator"}])


async def test_supplied_requirement_without_kind_must_still_be_mapped(tmp_path):
    supplied=RunInput(name="Supplied requirements",requirements=[{"id":"R-OWNER","statement":"Only tenant members read invoices","source":"owner"},
                                                                {"id":"R-SPEC","statement":"Sessions expire","source":"spec 4.2","source_kind":"specification"}])
    assert [r.source_kind for r in supplied.requirements]==["operator","specification"]
    store=Store(tmp_path)
    engine=Engine(store)
    run=engine.create(supplied)
    engine.start(run["id"])
    await engine.tasks[run["id"]]
    result=store.get(run["id"])
    assert result["status"]=="blocked" and result["stage"]=="threat_model"
    assert "has not been mapped" in result["error"]
    store.close()


def test_scanner_snapshot_raw_secret_stays_private_and_detects_added_files(tmp_path):
    source=tmp_path/"source"
    source.mkdir()
    (source/"app.py").write_text("value = input()\n")
    (source/".env").write_text("SYNTHETIC_SECRET=sentinel-local-fixture\n")
    (source/".semgrepignore").write_text("*\n")
    record=stage_source(str(source),tmp_path/"private")
    assert ".semgrepignore" in record["omitted"]
    assert (Path(record["path"])/".env").read_text().startswith("SYNTHETIC_SECRET=")
    assert verify_staging(record)
    (Path(record["path"])/"injected.py").write_text("print('unreviewed')")
    assert not verify_staging(record)


def test_scanner_staging_root_is_private_and_copy_is_discarded(tmp_path):
    source=tmp_path/"source"
    (source/"pkg").mkdir(parents=True)
    (source/"pkg"/"app.py").write_text("value = input()\n")
    (source/".env").write_text("SYNTHETIC_SECRET=sentinel-local-fixture\n")
    private=tmp_path/"private"
    private.mkdir(mode=0o755)
    record=stage_source(str(source),private)
    if os.name=="posix":
        assert private.stat().st_mode & 0o777==0o700
    with pytest.raises(ValueError,match="outside private scanner staging"):
        discard_staging({"path":str(source)},private)
    assert (source/".env").exists()
    # Staged files are read-only; removal still succeeds.
    assert discard_staging(record,private)
    assert not Path(record["path"]).exists() and private.exists()


async def test_staged_copy_is_discarded_once_whitebox_stage_completes(tmp_path):
    store=Store(tmp_path)
    try:
        engine=Engine(store)
        run=engine.create(RunInput(name="Staging lifetime"))
        source=tmp_path/"source"
        source.mkdir()
        (source/".env").write_text("SYNTHETIC_SECRET=sentinel-local-fixture\n")
        run["staging"]=stage_source(str(source),store.root/"scanner-inputs")
        store.save(run)
        engine.start(run["id"])
        await engine.tasks[run["id"]]
        result=store.get(run["id"])
        assert result["stage"]=="complete",result.get("error")
        assert result["staging"]["discarded"] is True
        assert not Path(run["staging"]["path"]).exists()
    finally:
        store.close()


def test_failed_staging_leaves_no_partial_copy_and_records_skipped_directories(tmp_path):
    source=tmp_path/"source"
    for name in ["app.py","build/deploy.py","dist/bundle.js","node_modules/pkg/index.js",".git/config"]:
        (source/name).parent.mkdir(parents=True,exist_ok=True)
        (source/name).write_text("AKIA-synthetic\n")
    if os.name=="posix":
        (source/"linked").symlink_to(source/"build",target_is_directory=True)
    private=tmp_path/"private"
    record=stage_source(str(source),private)
    # No scanner or model sees these directories, so the record names each of them.
    assert {"build/","dist/","node_modules/",".git/"}<=set(record["omitted"])
    assert os.name!="posix" or "linked/" in record["omitted"]
    assert [f["path"] for f in record["files"]]==["app.py"]
    discard_staging(record,private)
    with pytest.raises(ValueError,match="bounded snapshot limits"):
        stage_source(str(source),private,max_bytes=4)
    assert list(private.iterdir())==[]


async def test_staged_copy_never_outlives_a_failed_attempt_or_a_restart(tmp_path,monkeypatch):
    store=Store(tmp_path)
    try:
        engine=Engine(store)
        source=tmp_path/"source"
        source.mkdir()
        (source/".env").write_text("SYNTHETIC_SECRET=sentinel-local-fixture\n")
        # A blocked attempt drops its copy as well, not only a whitebox stage that completed.
        run=engine.create(RunInput(name="Blocked with a staged copy"))
        run["staging"]=stage_source(str(source),store.root/"scanner-inputs")
        store.save(run)
        async def blocked(run):
            raise PolicyError("Required model capability probe failed")
        monkeypatch.setattr(engine,"_preflight",blocked)
        engine.start(run["id"])
        await engine.tasks[run["id"]]
        result=store.get(run["id"])
        assert result["status"]=="blocked" and result["staging"]["discarded"] is True
        assert not Path(run["staging"]["path"]).exists()
        # At startup no attempt runs, so every copy still on disk, recorded or stray, is removed.
        orphan=engine.create(RunInput(name="Controller died while staged"))
        orphan["staging"]=stage_source(str(source),store.root/"scanner-inputs")
        store.save(orphan)
        stray=stage_source(str(source),store.root/"scanner-inputs")
        Engine(store)
        assert store.get(orphan["id"])["staging"]["discarded"] is True
        assert not Path(orphan["staging"]["path"]).exists() and not Path(stray["path"]).exists()
    finally:
        store.close()


async def test_resumed_scan_restages_only_an_unchanged_source(tmp_path,monkeypatch):
    store=Store(tmp_path)
    try:
        engine=Engine(store)
        source=tmp_path/"source"
        source.mkdir()
        (source/"app.py").write_text("value = input()\n")
        run=engine.create(RunInput(name="Resume after the copy was dropped"))
        run.update(mode="live",staging=stage_source(str(source),store.root/"scanner-inputs"),tool_results=[],tool_manifest={"tools":1},runtime_config_hash="h")
        run["manifest"].update(source_path=str(source),static_tools=["semgrep"])
        engine.discard_staging_copy(run)
        engine.runtime_configs["h"]={}
        engine.cancel_flags[run["id"]]=asyncio.Event()
        monkeypatch.setattr("vibe_audit.resource_manifest.resource_manifest",lambda config,tools:{"tools":1})
        scanned=[]
        class Runtime:
            async def run_scanner(self,tool,path,**kwargs):
                scanned.append(Path(path).joinpath("app.py").read_text())
                return {"status":"completed","findings":[],"gaps":[],"limitations":[]}
        monkeypatch.setattr(engine,"runtime",lambda run:Runtime())
        await engine._scan_source(run)
        assert scanned==["value = input()\n"] and run["staging"].get("discarded") is None
        engine.discard_staging_copy(run)
        run["tool_results"]=[]
        (source/"app.py").write_text("value = 'changed'\n")
        with pytest.raises(PolicyError,match="Source changed"):
            await engine._scan_source(run)
    finally:
        store.close()


async def test_trace_graph_and_requirement_gate(tmp_path):
    store=Store(tmp_path)
    engine,run=await demo(store)
    trace=store.trace(run["id"])
    kinds={entity["kind"] for entity in trace["entities"]}
    assert {"run","asset","dataflow","threat","requirement","case","execution","evidence","finding"}<=kinds
    assert {"violates","verified_by","executed_as","observed_in","supports"}<={link["relation"] for link in trace["links"]}
    bad=copy.deepcopy(run)
    bad["threat_model"]["requirements"][0]["threat_ids"]=[]
    bad["threat_model"]["hash"]=sealed(bad["threat_model"])
    with pytest.raises(PolicyError,match="traceability"):
        engine.policy.threat_gate(bad)
    store.close()


@pytest.mark.parametrize("backend",["sqlite","postgres"])
async def test_graph_and_job_commit_rollback_is_atomic(tmp_path,monkeypatch,backend):
    url=os.getenv("VIBEAUDIT_TEST_DATABASE_URL") if backend=="postgres" else None
    if backend=="postgres" and not url:
        pytest.skip("Provide dedicated PostgreSQL integration database")
    store=Store(tmp_path,url)
    _,run=await demo(store)
    job=store.job(run["id"],run["cases"][0])
    store.update_job(job,"sent",{"side_effects":True})
    original=store.get(run["id"])
    execute=store._execute
    def fail(sql,args=()):
        if sql.startswith("INSERT INTO entity_versions"):
            raise RuntimeError("Injected graph persistence failure")
        return execute(sql,args)
    monkeypatch.setattr(store,"_execute",fail)
    run["name"]="must rollback"
    with pytest.raises(RuntimeError,match="Injected"):
        store.finish_job(job,{"status":"pass"},run)
    assert store.get(run["id"])["name"]==original["name"]
    assert next(j for j in store.jobs(run["id"]) if j["id"]==job)["status"]=="sent"
    monkeypatch.setattr(store,"_execute",execute)
    restarted=Engine(store,url)
    with pytest.raises(PolicyError,match="outcome_unknown"):
        restarted.start(run["id"],resume=True)
    store.close()


def test_workspace_settings_catalog_and_linked_retest(tmp_path):
    app=create_app(tmp_path,testing=True)
    with TestClient(app) as client:
        csrf=client.get("/api/session",headers={"X-VibeAudit-Token":app.state.session_token}).json()["csrf_token"]
        client.headers["X-CSRF-Token"]=csrf
        headers={"x-csrf-token":csrf}
        profile={"id":"commander","role":"commander","provider":"openai","model_id":"operator-selects-model","family":"openai","endpoint":"https://api.openai.com/v1","credential_env":"VIBEAUDIT_OPENAI_KEY"}
        assert client.put("/api/models/commander",json=profile,headers=headers).status_code==200
        assert client.get("/api/models").json()["models"][0]["credential_env"]=="VIBEAUDIT_OPENAI_KEY"
        assert client.put("/api/projects/p1",json={"id":"p1","name":"Saved setup","configuration":{"mode":"demo"}},headers=headers).status_code==200
        assert client.get("/api/projects").json()["projects"][0]["id"]=="p1"
        catalogs=client.get("/api/catalogs")
        assert catalogs.status_code==200
        assert len(catalogs.json()["entries"])>400
        # Run the async engine on TestClient's loop, preserving the real API store.
        engine,run=client.portal.call(demo,app.state.store)
        trace=client.get(f"/api/runs/{run['id']}/trace")
        assert trace.status_code==200 and trace.json()["links"]
        body={"name":"Fixed deployment","source_path":"","deployment_id":"fixed-v2","finding_ids":[run["findings"][0]["id"]]}
        response=client.post(f"/api/runs/{run['id']}/retest",json=body,headers=headers)
        assert response.status_code==201,response.text
        child=response.json()
        assert child["manifest"]["parent_run_id"]==run["id"]
        assert child["status"]=="created" and child["executions"]==[]
        assert len(child["manifest"]["cases"])==3
        finding_id=run["findings"][0]["id"]
        links=client.get(f"/api/runs/{child['id']}/trace").json()["links"]
        assert {(l["target_kind"],l["target_id"]) for l in links if l["relation"]=="retests"}=={("run",run["id"]),("finding",finding_id)}
        markdown=client.get(f"/api/runs/{child['id']}/report",params={"format":"markdown"}).text
        assert "Retest of: "+run["id"]+" (findings: "+finding_id.replace("_","\\_")+")" in markdown
        sarif=client.get(f"/api/runs/{child['id']}/report",params={"format":"sarif"}).json()["runs"][0]["properties"]
        assert sarif=={"runId":child["id"],"retestOf":run["id"],"retestedFindingIds":[finding_id]}
        assert "retestOf" not in client.get(f"/api/runs/{run['id']}/report",params={"format":"sarif"}).json()["runs"][0]["properties"]
        assert "Retest of" not in client.get(f"/api/runs/{run['id']}/report",params={"format":"markdown"}).text


def test_finding_decision_needs_independent_execution_evidence(tmp_path):
    app=create_app(tmp_path,testing=True)
    with TestClient(app) as client:
        csrf=client.get("/api/session",headers={"X-VibeAudit-Token":app.state.session_token}).json()["csrf_token"]
        client.headers["X-CSRF-Token"]=csrf
        headers={"x-csrf-token":csrf}
        _,run=client.portal.call(demo,app.state.store)
        observed=next(f for f in run["findings"] if f["agent_ids"]==["blackbox-worker"])
        execution={x["case_id"]:x["evidence_id"] for x in run["executions"]}
        producers={a["id"]:a["producer"] for a in run["artifacts"]}
        snapshot=next(key for key,producer in producers.items() if producer=="source-snapshot")
        reviews=[key for key,producer in producers.items() if producer.startswith("reviewer-")]
        # A hypothesis some review did not raise, so that review is not its own evidence.
        hypothesis=next(f for f in run["findings"] if f["state"]=="hypothesis" and set(reviews)-set(f["evidence_ids"]))
        review=next(key for key in reviews if key not in hypothesis["evidence_ids"])
        def decide(finding,decision,*evidence,threats=()):
            url=f"/api/runs/{run['id']}/findings/{finding['id']}/decision"
            body={"decision":decision,"rationale":"Operator retest","evidence_ids":list(evidence),"threat_ids":list(threats)}
            return client.post(url,json=body,headers=headers)
        # An observed violation is cleared by a linked retest, never by another pass in the same run.
        for decision in ["refuted","inconclusive"]:
            response=decide(observed,decision,execution["C-002"])
            assert response.status_code==409 and "retest" in response.json()["detail"],response.text
        for decision,evidence,threats,reason in [
                ("refuted",[snapshot],["T-001"],"black-box execution"),
                ("inconclusive",[review],["T-001"],"black-box execution"),
                ("refuted",[execution["C-002"],snapshot],["T-001"],"black-box execution"),
                ("refuted",[execution["C-002"]],[],"Name the threats"),
                ("refuted",[execution["C-002"]],["T-404"],"Name the threats"),
                # C-003 tests T-002, so it says nothing about T-001.
                ("inconclusive",[execution["C-003"]],["T-001"],"tests the finding's threats"),
                ("refuted",[execution["C-003"]],["T-002"],"security property held"),
                # C-002 passed, but C-001 observed a T-001 violation in the same run.
                ("refuted",[execution["C-002"]],["T-001"],"observed a violation"),
                ("refuted",[str(uuid.uuid4())],["T-001"],"belong to this run")]:
            response=decide(hypothesis,decision,*evidence,threats=threats)
            assert response.status_code==409 and reason in response.json()["detail"],response.text
        assert app.state.store.get(run["id"])["findings"]==run["findings"]
        response=decide(hypothesis,"inconclusive",execution["C-003"],threats=["T-002"])
        assert response.status_code==200,response.text
        # A run whose only T-001 execution passed lets that pass refute the hypothesis.
        stored=app.state.store.get(run["id"])
        stored["executions"]=[e for e in stored["executions"] if e["case_id"]!="C-001"]
        stored["findings"]=[f for f in stored["findings"] if f["id"]!=observed["id"]]
        app.state.store.save(stored)
        response=decide(hypothesis,"refuted",execution["C-002"],threats=["T-001"])
        assert response.status_code==200,response.text
        decided=next(f for f in response.json()["findings"] if f["id"]==hypothesis["id"])
        assert decided["state"]=="refuted"
        assert [d["previous_state"] for d in decided["decisions"]]==["hypothesis","inconclusive"]
        assert [d["threat_ids"] for d in decided["decisions"]]==[["T-002"],["T-001"]]


async def test_postgres_checkpoints_and_resume_do_not_duplicate_executions(tmp_path):
    url=os.getenv("VIBEAUDIT_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Provide dedicated PostgreSQL integration database")
    store=Store(tmp_path,url)
    engine=Engine(store,url)
    run=engine.create(RunInput(name="PostgreSQL durable checkpoint integration"))
    engine.start(run["id"])
    await engine.tasks[run["id"]]
    original=store.get(run["id"])
    assert original["stage"]=="complete",original.get("error")
    assert len(original["executions"])==3
    checkpoints=store._execute("SELECT count(*) FROM checkpoints WHERE thread_id=?",(run["id"],)).fetchone()[0]
    assert checkpoints>0
    restarted=Engine(store,url)
    restarted.start(run["id"],resume=True)
    await restarted.tasks[run["id"]]
    resumed=store.get(run["id"])
    assert [e["id"] for e in resumed["executions"]]==[e["id"] for e in original["executions"]]
    assert resumed["usage"]==original["usage"]
    store.close()


# MULE_INTERNAL has no Python codec: psycopg raises NotSupportedError when asked for the connection's Python encoding.
@pytest.mark.parametrize("server,client",[("SQL_ASCII","SQL_ASCII"),("UTF8","SQL_ASCII"),("SQL_ASCII","UTF8"),("UTF8","MULE_INTERNAL")])
def test_store_refuses_a_non_utf8_postgres_database(tmp_path,monkeypatch,server,client):
    import psycopg
    closed=[]
    class Info:
        @property
        def encoding(self):
            if client=="MULE_INTERNAL":raise psycopg.NotSupportedError("codec not available in Python: 'MULE_INTERNAL'")
            return {"UTF8":"utf-8","SQL_ASCII":"ascii"}[client]
        @staticmethod
        def parameter_status(name):return {"server_encoding":server,"client_encoding":client}.get(name)
    class Conn:
        info=Info()
        def close(self):closed.append(True)
        def execute(self,*_):raise AssertionError("No statement may run on a non-UTF8 database")
    monkeypatch.setattr(psycopg,"connect",lambda *a,**k:Conn())
    with pytest.raises(ValueError,match="UTF8"):
        Store(tmp_path/"data","postgresql://synthetic/db")
    assert closed==[True]
