"""Local configuration, traceability and retest endpoints (under API session policy)."""
from __future__ import annotations

from copy import deepcopy
import asyncio
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .domain import ModelProfile, RunInput, now
from .adapters import case_headers_allowed, model_header_vocabulary
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
    # A finding without threat links names the threats its counterevidence tests; the decision records them.
    threat_ids: list[str] = Field(default_factory=list, max_length=100)


class CleanupAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attestation: str = Field(min_length=1, max_length=4000)


def workspace_router(store, engine, source_roots, *, session):
    """session: the dependency that proves the local session and CSRF token. It is required, so these routes
    keep their own check even if the router is mounted on an app without the console's middleware."""
    router = APIRouter(prefix="/api", dependencies=[Depends(session)])

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
        cases = parent["cases"]
        selected = [f for f in parent["findings"] if f["id"] in set(data.finding_ids)]
        threats = {t for f in selected for t in f.get("threat_ids") or []}
        if len(selected) != len(set(data.finding_ids)):
            raise PolicyError("Retest references a finding outside the parent run")
        if any(not f.get("threat_ids") for f in selected):
            raise PolicyError("Selected findings lack threat traceability; map them in a new assessment before a retest")
        if threats:
            # A retest re-checks what was selected: only the cases that test those findings' threats.
            cases = [c for c in cases if threats & set(c.get("threat_ids", []))]
            if not cases:
                raise PolicyError("No case of the original assessment tests the selected findings' threats")
        if cases:
            manifest["cases"] = [{k: v for k, v in case.items() if k not in
                                  {"hash", "source_digest", "threat_model_hash"}} for case in cases]
        # A retest keeps the parent's manifest, so a model-designed case whose headers that manifest never listed
        # would only be refused later by the case gate, after the white-box stage had spent its budget. Say so now.
        refused = sorted(str(case.get("id", "?")) for case in manifest.get("cases", []) if case.get("designed_by") == "model"
                         and not all(case_headers_allowed(step.get("headers"), model_designed=True,
                                                          vocabulary=model_header_vocabulary(manifest, step.get("method", "GET"), step.get("path")))
                                     for step in [case, *[p for p in case.get("preconditions", []) if isinstance(p, dict)]]))
        if refused:
            raise PolicyError("This retest would copy model-designed cases (" + ", ".join(refused) + ") whose headers the original "
                              "run's allowed_requests[].model_headers do not list, so the case gate would refuse them. A retest cannot "
                              "change the original scope: create a new assessment that lists those header values for their method and "
                              "path, or supply operator-written cases.")
        model = RunInput.model_validate(manifest)
        if model.mode == "live":
            path = Path(model.source_path).resolve()
            if not any(path == root or path.is_relative_to(root) for root in source_roots):
                raise HTTPException(403, "Source directory is outside configured source roots")
            model = model.model_copy(update={"source_path": str(path)})
        return engine.create(model)

    @router.post("/runs/{run_id}/findings/{finding_id}/decision")
    async def decision(run_id: str, finding_id: str, data: FindingDecision, request: Request):
        # Read, change and save under the store's lock, on one worker thread: a second decision, or the engine's own
        # save, waits its turn instead of overwriting this one. The lock is re-entrant for that thread, so the store's
        # own methods still take it; the event loop never holds it while waiting on the thread, which would deadlock.
        return await asyncio.to_thread(decide, run_id, finding_id, data, request.state.actor)

    def decide(run_id: str, finding_id: str, data: FindingDecision, actor: str):
        with store.lock:
            return decide_locked(run_id, finding_id, data, actor)

    def decide_locked(run_id: str, finding_id: str, data: FindingDecision, actor: str):
        run = store.get(run_id)
        if run["status"] in {"running", "cancelling"}:
            raise PolicyError("Cannot change a finding while its assessment is running")
        finding = next((f for f in run["findings"] if f["id"] == finding_id), None)
        if finding is None:
            raise HTTPException(404, "Finding not found")
        # A pass of another case, or a later pass of the same one, does not undo an observed violation.
        if finding["state"] in {"validated_dynamic", "resolved_in_retest"}:
            raise PolicyError("An observed violation stands; verify the fix in a linked retest run")
        records = {a["id"]: a for a in run["artifacts"]}
        if not set(data.evidence_ids) <= records.keys():
            raise PolicyError("Counterevidence must belong to this run")
        if set(data.evidence_ids) & set(finding["evidence_ids"]):
            raise PolicyError("A finding's own evidence cannot be cited against it")
        # Model reviews, scanner output and the source snapshot restate what produced the finding;
        # only an observed black-box execution is independent of it.
        if any(records[key]["producer"] != "blackbox-worker" for key in data.evidence_ids):
            raise PolicyError("Counterevidence must be a black-box execution record")
        linked = set(finding.get("threat_ids") or [])
        if linked and not set(data.threat_ids) <= linked:
            raise PolicyError("The finding's own threat links decide which executions can be cited")
        threats = linked or set(data.threat_ids)
        known = {t["id"] for t in (run.get("threat_model") or {}).get("threats", [])}
        if not threats or not threats <= known:
            raise PolicyError("Name the threats from this run's threat model that the counterevidence tests")
        cases = {c["id"]: c for c in run.get("cases", []) if isinstance(c, dict) and c.get("id")}
        def tests_threats(execution):
            return bool(threats & set(cases.get(execution.get("case_id"), {}).get("threat_ids", [])))
        executions = {e.get("evidence_id"): e for e in run["executions"]}
        if not all(tests_threats(executions.get(key, {})) for key in data.evidence_ids):
            raise PolicyError("Counterevidence must come from a case that tests the finding's threats")
        try:
            statuses = [store.evidence(records[key], run_id)["content"]["result"]["status"] for key in data.evidence_ids]
        except (ValueError, OSError):
            raise HTTPException(409, "Evidence integrity check failed") from None
        if data.decision == "refuted" and "pass" not in statuses:
            raise PolicyError("Refuting a finding needs an execution in which the security property held")
        if data.decision == "refuted" and any(e["status"] == "fail" for e in run["executions"] if tests_threats(e)):
            raise PolicyError("A case testing these threats observed a violation in this run; the finding cannot be refuted")
        if data.decision == "refuted":
            from .contracts import threat_coverage_outcome
            if threat_coverage_outcome(run, threats, evidence_ids=set(data.evidence_ids)) != "pass":
                raise PolicyError("Refuting a finding requires cited passing evidence for every related case, repetition and threat")
        entry = {**data.model_dump(), "threat_ids": sorted(threats), "at": now(), "actor": actor, "previous_state": finding["state"]}
        finding.setdefault("decisions", []).append(entry)
        finding["state"] = data.decision
        finding["counterevidence"] = data.evidence_ids
        engine.event(run, f"Operator {actor} recorded an evidence-linked decision for " + finding_id)
        return run

    @router.post("/runs/{run_id}/reconcile")
    async def reconcile(run_id: str, data: CleanupAttestation, request: Request):
        def reconcile_locked():
            with store.lock:
                return engine.reconcile(run_id, data.attestation, request.state.actor)
        return await asyncio.to_thread(reconcile_locked)

    return router
