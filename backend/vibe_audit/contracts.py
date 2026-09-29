"""Versioned, bounded contracts for model proposals and security traceability."""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CORE_REVIEW_QUESTIONS = [
    "Authentication, session revocation, authorization and cross-tenant boundaries",
    "Untrusted input dataflow to sensitive operations, including cross-file flows",
    "Secrets, dependencies, deployment and security configuration",
    "AI tool permissions, RAG isolation, memory and external-content trust boundaries",
]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceReference(Contract):
    file: str = Field(min_length=1, max_length=500)
    line: int = Field(ge=1)
    quote: str = Field(min_length=1, max_length=2000)

    @field_validator("file")
    @classmethod
    def relative(cls, value):
        if "\\" in value or ":" in value or PurePosixPath(value).is_absolute() or ".." in PurePosixPath(value).parts:
            raise ValueError("A relative snapshot path is required")
        return value


class Asset(Contract):
    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=300)
    kind: str = Field(min_length=1, max_length=80)
    tenant_ids: list[str] = Field(default_factory=list, max_length=100)
    source_refs: list[SourceReference] = Field(default_factory=list, max_length=30)


class Dataflow(Contract):
    id: str = Field(min_length=1, max_length=100)
    source: str
    target: str
    boundary: str = Field(min_length=1, max_length=500)
    attacker_control: str = Field(default="unknown", max_length=1000)
    source_refs: list[SourceReference] = Field(default_factory=list, max_length=30)


class SecurityRequirement(Contract):
    id: str = Field(min_length=1, max_length=100)
    statement: str = Field(min_length=1, max_length=3000)
    threat_ids: list[str] = Field(default_factory=list, max_length=100)
    source_kind: Literal["operator", "specification", "derived"] = "derived"
    source: str = Field(min_length=1, max_length=3000)
    standard_ids: list[str] = Field(default_factory=list, max_length=50)


class Threat(Contract):
    id: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=500)
    asset_ids: list[str] = Field(min_length=1, max_length=100)
    category: str = Field(min_length=1, max_length=300)
    preconditions: list[str | dict] = Field(default_factory=list, max_length=100)
    invariant: str = Field(min_length=1, max_length=3000)
    impact: str = Field(min_length=1, max_length=3000)
    control_evidence: list[SourceReference] = Field(default_factory=list, max_length=30)
    assumptions: list[str] = Field(default_factory=list, max_length=100)
    unknowns: list[str] = Field(default_factory=list, max_length=100)
    requirement_id: str = Field(min_length=1, max_length=100)
    dataflow_ids: list[str] = Field(default_factory=list, max_length=100)
    testability: Literal["automated", "blocked"]
    blocked_reason: str | None = None


class ThreatModelProposal(Contract):
    id: str = Field(min_length=1, max_length=100)
    version: int = Field(default=1, ge=1)
    assets: list[Asset] = Field(min_length=1, max_length=500)
    dataflows: list[Dataflow] = Field(min_length=1, max_length=1000)
    threats: list[Threat] = Field(min_length=1, max_length=500)
    requirements: list[SecurityRequirement] = Field(default_factory=list, max_length=500)
    roles: list[dict] = Field(default_factory=list, max_length=100)
    assumptions: list[str] = Field(default_factory=list, max_length=100)
    unknowns: list[str] = Field(default_factory=list, max_length=100)
    standards: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def references(self):
        for items in (self.assets, self.dataflows, self.threats, self.requirements):
            if len({item.id for item in items}) != len(items):
                raise ValueError("Duplicate graph identifier")
        assets = {item.id for item in self.assets}
        flows = {item.id for item in self.dataflows}
        threats = {item.id for item in self.threats}
        for flow in self.dataflows:
            if flow.source not in assets or flow.target not in assets:
                raise ValueError("Dataflow references an unknown asset")
        for threat in self.threats:
            if not set(threat.asset_ids) <= assets or not set(threat.dataflow_ids) <= flows:
                raise ValueError("Threat references an unknown graph object")
            if threat.testability == "blocked" and not threat.blocked_reason:
                raise ValueError("Blocked threat needs a concrete reason")
        for requirement in self.requirements:
            if not set(requirement.threat_ids) <= threats:
                raise ValueError("Requirement references an unknown threat")
        return self


class ReviewFinding(Contract):
    title: str = Field(min_length=1, max_length=500)
    severity: Literal["critical", "high", "medium", "low", "info"]
    description: str = Field(min_length=1, max_length=5000)
    file: str | None = None
    line: int | None = Field(default=None, ge=1)
    cwe: str | None = Field(default=None, pattern=r"^CWE-[1-9][0-9]*$")
    source_refs: list[SourceReference] = Field(default_factory=list, max_length=30)
    asset_ids: list[str] = Field(default_factory=list, max_length=100)


class ReviewProposal(Contract):
    findings: list[ReviewFinding] = Field(default_factory=list, max_length=500)
    gaps: list[str] = Field(default_factory=list, max_length=200)


class ArchitectureProposal(Contract):
    assets: list[Asset] = Field(default_factory=list, max_length=500)
    dataflows: list[Dataflow] = Field(default_factory=list, max_length=1000)
    roles: list[dict] = Field(default_factory=list, max_length=100)
    gaps: list[str] = Field(default_factory=list, max_length=200)


class ReportOrderProposal(Contract):
    finding_ids: list[str] = Field(default_factory=list, max_length=5000)


class CommanderProposal(Contract):
    reviewer_order: list[str] = Field(min_length=3, max_length=3)
    focus: list[str] = Field(default_factory=list, max_length=30)
    rationale: str = Field(min_length=1, max_length=3000)


def verify_source_references(references: list[dict], source: dict) -> None:
    files = {item["path"]: item["content"] for item in source["files"]}
    for raw in references:
        ref = SourceReference.model_validate(raw)
        if ref.file not in files:
            raise ValueError("Evidence cites a file outside the frozen snapshot")
        lines = files[ref.file].splitlines()
        quoted_lines = ref.quote.splitlines()
        start = ref.line - 1
        if start >= len(lines) or "\n".join(lines[start:start + len(quoted_lines)]).find(ref.quote) == -1:
            raise ValueError("Evidence quote does not match its snapshot location")


def complete_requirements(model: dict, supplied: list[dict]) -> list[dict]:
    """Preserve provenance: a model-derived invariant is never an operator fact."""
    by_id = {item["id"]: dict(item) for item in model.get("requirements", [])}
    for item in by_id.values():
        item["source_kind"]="derived"
    for raw in supplied:
        item = SecurityRequirement.model_validate(raw).model_dump()
        if item["id"] in by_id and by_id[item["id"]]["statement"] != item["statement"]:
            raise ValueError("Model changed an operator-provided security requirement")
        by_id[item["id"]] = item
    for threat in model["threats"]:
        key = threat["requirement_id"]
        if key not in by_id:
            by_id[key] = SecurityRequirement(id=key, statement=threat["invariant"], source_kind="derived", source="Threat invariant; application owner must verify business semantics").model_dump()
        refs = by_id[key]["threat_ids"]
        if threat["id"] not in refs:
            refs.append(threat["id"])
    return list(by_id.values())
