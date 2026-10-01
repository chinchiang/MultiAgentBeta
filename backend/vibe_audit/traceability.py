"""Materialize immutable graph versions and their explicit evidence relationships."""
from __future__ import annotations

from .domain import digest


def _ids(value):
    return value if isinstance(value, list) else []


def entities_and_links(run: dict) -> tuple[list[dict], list[dict]]:
    # Model-designed cases are saved before the gates reject them, and the failed run must still be saved.
    # A missing or malformed field therefore drops its links instead of failing the save.
    entities, links = [], []
    def entity(kind, identity, value):
        entities.append({"kind": kind, "id": str(identity), "version": digest(value), "value": value})
    def link(source_kind, source_id, target_kind, target_id, relation):
        if source_id is None or target_id is None:
            return
        links.append({"source_kind": source_kind, "source_id": str(source_id), "target_kind": target_kind, "target_id": str(target_id), "relation": relation})
    entity("run", run["id"], run["manifest"])
    # A retest points back at what it re-checks; those entities live in the parent run's own trace.
    link("run", run["id"], "run", run["manifest"].get("parent_run_id"), "retests")
    for finding_id in _ids(run["manifest"].get("parent_finding_ids")):
        link("run", run["id"], "finding", finding_id, "retests")
    tm = run.get("threat_model") or {}
    if tm:
        entity("threat_model", tm.get("id"), tm)
    for kind, key in (("asset", "assets"), ("dataflow", "dataflows"), ("threat", "threats"), ("requirement", "requirements")):
        for value in _ids(tm.get(key)):
            if not isinstance(value, dict):
                continue
            entity(kind, value.get("id"), value)
            link("run", run["id"], kind, value.get("id"), "contains")
            if kind == "dataflow":
                link("asset", value.get("source"), kind, value.get("id"), "sends")
                link(kind, value.get("id"), "asset", value.get("target"), "reaches")
            elif kind == "threat":
                for asset_id in _ids(value.get("asset_ids")):
                    link("asset", asset_id, kind, value.get("id"), "exposed_to")
                link(kind, value.get("id"), "requirement", value.get("requirement_id"), "violates")
    for case in _ids(run.get("cases")):
        if not isinstance(case, dict):
            continue
        entity("case", case.get("id"), case)
        link("requirement", case.get("requirement_id"), "case", case.get("id"), "verified_by")
        for threat_id in _ids(case.get("threat_ids")):
            link("threat", threat_id, "case", case.get("id"), "tested_by")
    for execution in run.get("executions", []):
        entity("execution", execution["id"], execution)
        link("case", execution["case_id"], "execution", execution["id"], "executed_as")
        if execution.get("evidence_id"):
            link("execution", execution["id"], "evidence", execution["evidence_id"], "observed_in")
    for evidence in run.get("artifacts", []):
        entity("evidence", evidence["id"], evidence)
    for finding in run.get("findings", []):
        entity("finding", finding["id"], finding)
        for evidence_id in finding.get("evidence_ids", []):
            link("evidence", evidence_id, "finding", finding["id"], "supports")
        for threat_id in finding.get("threat_ids", []):
            link("threat", threat_id, "finding", finding["id"], "realized_as")
    return entities, links
