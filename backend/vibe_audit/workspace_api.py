"""Local configuration, traceability and retest endpoints (under API session policy)."""
from __future__ import annotations

from copy import deepcopy
import asyncio
import re
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .domain import ModelProfile, RunInput, now
from .policy import PolicyError


class ProjectSetting(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    name: str = Field(min_length=1, max_length=160)
    configuration: RunInput


class RetestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    source_path: str
    deployment_id: str = Field(min_length=1, max_length=200)
    finding_ids: list[str] = Field(min_length=1, max_length=100)


class FindingDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(pattern=r"^(refuted|inconclusive)$")
    rationale: str = Field(min_length=1, max_length=4000)
    evidence_ids: list[str] = Field(min_length=1, max_length=100)


class CleanupAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attestation: str = Field(min_length=1, max_length=4000)


def workspace_router(store, engine, source_roots):
    router = APIRouter(prefix="/api")

    @router.get("/projects")
    async def projects():
        return {"projects": store.settings("project")}

    @router.put("/projects/{project_id}")
    async def save_project(project_id: str, data: ProjectSetting):
        if project_id != data.id:
            raise HTTPException(422, "Project ID mismatch")
        value = data.model_dump()
        store.save_setting("project", data.id, value)
        return value

    @router.get("/models")
    async def models():
        return {"models": store.settings("model")}

    @router.put("/models/{model_id}")
    async def save_model(model_id: str, profile: ModelProfile):
        if model_id != profile.id:
            raise HTTPException(422, "Agent ID mismatch")
        value = profile.model_dump()
        store.save_setting("model", model_id, value)
        return value

    @router.get("/catalogs")
    async def catalogs(standard: str | None = None):
        from .catalog import load_catalogs
        registry = await asyncio.to_thread(load_catalogs)
        return {"manifest": registry.manifest(), "entries": registry.entries(standard)}

    @router.get("/runs/{run_id}/trace")
    async def trace(run_id: str):
        return store.trace(run_id)

    @router.post("/runs/{run_id}/retest", status_code=201)
    async def retest(run_id: str, data: RetestRequest):
        from pathlib import Path
        parent = store.get(run_id)
        if parent["status"] in {"created", "running", "cancelling"}:
            raise PolicyError("Finish or stop the original assessment before creating a retest")
        manifest = deepcopy(parent["manifest"])
        manifest.update(name=data.name, source_path=data.source_path, deployment_id=data.deployment_id,
                        parent_run_id=run_id, parent_finding_ids=data.finding_ids)
        # Original operator cases retain their assertions; new evidence receives new IDs/hashes.
        if parent["cases"]:
            manifest["cases"] = [{k: v for k, v in case.items() if k not in
                                  {"hash", "source_digest", "threat_model_hash"}} for case in parent["cases"]]
        model = RunInput.model_validate(manifest)
        if model.mode == "live":
            path = Path(model.source_path).resolve()
            if not any(path == root or path.is_relative_to(root) for root in source_roots):
                raise HTTPException(403, "Source directory is outside configured source roots")
        return engine.create(model)

    @router.post("/runs/{run_id}/findings/{finding_id}/decision")
    async def decision(run_id: str, finding_id: str, data: FindingDecision):
        run = store.get(run_id)
        if run["status"] in {"running", "cancelling"}:
            raise PolicyError("Cannot change a finding while its assessment is running")
        finding = next((f for f in run["findings"] if f["id"] == finding_id), None)
        if finding is None:
            raise HTTPException(404, "Finding not found")
        records = {a["id"]: a for a in run["artifacts"]}
        if not set(data.evidence_ids) <= records.keys():
            raise PolicyError("Counterevidence must belong to this run")
        if set(data.evidence_ids) & set(finding["evidence_ids"]):
            raise PolicyError("A finding's own evidence cannot be cited against it")
        # Model reviews, scanner output and the source snapshot restate what produced the finding;
        # only an observed black-box execution is independent of it.
        if any(records[key]["producer"] != "blackbox-worker" for key in data.evidence_ids):
            raise PolicyError("Counterevidence must be a black-box execution record")
        statuses = [store.evidence(records[key], run_id)["content"]["result"]["status"] for key in data.evidence_ids]
        if data.decision == "refuted" and "pass" not in statuses:
            raise PolicyError("Refuting a finding needs an execution in which the security property held")
        entry = {**data.model_dump(), "at": now(), "actor": "local_operator", "previous_state": finding["state"]}
        finding.setdefault("decisions", []).append(entry)
        finding["state"] = data.decision
        finding["counterevidence"] = data.evidence_ids
        engine.event(run, "Local operator recorded an evidence-linked decision for " + finding_id)
        return run

    @router.post("/runs/{run_id}/reconcile")
    async def reconcile(run_id: str, data: CleanupAttestation):
        return engine.reconcile(run_id, data.attestation)

    return router
