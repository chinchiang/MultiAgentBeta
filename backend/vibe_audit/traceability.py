"""Materialize immutable graph versions and their explicit evidence relationships."""
from __future__ import annotations

from .domain import digest


def entities_and_links(run: dict) -> tuple[list[dict], list[dict]]:
    entities, links = [], []
    def entity(kind, identity, value):
        entities.append({"kind": kind, "id": str(identity), "version": digest(value), "value": value})
    def link(source_kind, source_id, target_kind, target_id, relation):
        links.append({"source_kind": source_kind, "source_id": str(source_id), "target_kind": target_kind, "target_id": str(target_id), "relation": relation})
    entity("run", run["id"], run["manifest"])
    tm = run.get("threat_model") or {}
    if tm:
        entity("threat_model", tm["id"], tm)
    for kind, key in (("asset", "assets"), ("dataflow", "dataflows"), ("threat", "threats"), ("requirement", "requirements")):
        for value in tm.get(key, []):
            entity(kind, value["id"], value)
            link("run", run["id"], kind, value["id"], "contains")
            if kind == "dataflow":
                link("asset", value["source"], kind, value["id"], "sends")
                link(kind, value["id"], "asset", value["target"], "reaches")
            elif kind == "threat":
                for asset_id in value["asset_ids"]:
                    link("asset", asset_id, kind, value["id"], "exposed_to")
                link(kind, value["id"], "requirement", value["requirement_id"], "violates")
    for case in run.get("cases", []):
        entity("case", case["id"], case)
        link("requirement", case["requirement_id"], "case", case["id"], "verified_by")
        for threat_id in case["threat_ids"]:
            link("threat", threat_id, "case", case["id"], "tested_by")
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
