import asyncio
import copy
import json
import os
from pathlib import Path
import uuid

import pytest
from fastapi.testclient import TestClient

from vibe_audit.api import create_app
from vibe_audit.contracts import complete_requirements, verify_source_references
from vibe_audit.domain import RunInput
from vibe_audit.policy import PolicyError, sealed
from vibe_audit.service import Engine
from vibe_audit.staging import stage_source, verify_staging
from vibe_audit.store import Store


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
                {"file":"../app.py","line":2,"quote":"return tenant_id"}):
        with pytest.raises(ValueError):
            verify_source_references([ref],source)


def test_model_cannot_claim_operator_requirements_or_change_supplied_rules():
    model={"requirements":[{"id":"R1","statement":"tenant isolation","threat_ids":[],"source_kind":"operator","source":"model assertion","standard_ids":[]}],
           "threats":[{"id":"T1","requirement_id":"R1","invariant":"tenant isolation"}]}
    result=complete_requirements(model,[])
    assert result[0]["source_kind"]=="derived"
    assert result[0]["threat_ids"]==["T1"]
    with pytest.raises(ValueError,match="changed"):
        complete_requirements(model,[{"id":"R1","statement":"a different operator policy","source":"owner","source_kind":"operator"}])


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
        csrf=client.get("/api/session").json()["csrf_token"]
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
