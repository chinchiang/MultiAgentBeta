"""Versioned, bounded contracts for model proposals and security traceability."""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Literal

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


class ChallengeItem(Contract):
    """One counter-evidence observation about an existing finding. Never a verdict."""
    finding_id: str = Field(min_length=1, max_length=100)
    counterevidence: str = Field(default="", max_length=5000)
    missing_evidence: str = Field(default="", max_length=5000)

    @model_validator(mode="after")
    def substantive(self):
        # The challenger round asks for evidence content: an empty challenge
        # would only inflate the record without saying anything.
        if not self.counterevidence.strip() and not self.missing_evidence.strip():
            raise ValueError("A challenge needs counterevidence or missing evidence")
        return self


class ChallengeProposal(Contract):
    challenges: list[ChallengeItem] = Field(default_factory=list, max_length=500)


class ArchitectureProposal(Contract):
    assets: list[Asset] = Field(default_factory=list, max_length=500)
    dataflows: list[Dataflow] = Field(default_factory=list, max_length=1000)
    roles: list[dict] = Field(default_factory=list, max_length=100)
    gaps: list[str] = Field(default_factory=list, max_length=200)


# A model writes these texts and the black-box worker holds them while a hostile target answers, so each is bounded.
OracleText = Annotated[str, Field(min_length=1, max_length=120)]


class CaseOracle(Contract):
    kind: Literal["deny_sensitive", "canary_absent", "no_unauthorized_commit"]
    forbidden_text: list[OracleText] = Field(default_factory=list, max_length=20)
    allowed_statuses: list[int] = Field(default_factory=list, max_length=20)
    required_observations: list[str] = Field(min_length=1, max_length=20)
    expected_role: str | None = Field(default=None, max_length=100)


class CaseControl(Contract):
    """A positive control only reads the fixture it proves: every executor requires a GET, a 2xx and a marker."""
    name: str = Field(min_length=1, max_length=100)
    method: Literal["GET"] = "GET"
    path: str = Field(pattern=r"^/", max_length=2000)
    identity: str | None = Field(default=None, max_length=100)
    expected_status: int = Field(ge=200, le=299)
    required_text: list[OracleText] = Field(min_length=1, max_length=20)
    headers: dict[str, str] = Field(default_factory=dict, max_length=24)


class CaseProposal(Contract):
    """A model-designed case. The engine adds provenance, fixture scope and hashes before sealing."""
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,100}$")
    title: str = Field(min_length=1, max_length=500)
    threat_ids: list[str] = Field(min_length=1, max_length=20)
    requirement_id: str = Field(min_length=1, max_length=100)
    adapter: Literal["http", "ai_http"]
    method: Literal["GET", "POST"] = "GET"
    path: str = Field(pattern=r"^/", max_length=2000)
    headers: dict[str, str] = Field(default_factory=dict, max_length=24)
    body: dict | list | str | int | float | bool | None = None
    identity: str | None = Field(default=None, max_length=100)
    preconditions: list[CaseControl] = Field(default_factory=list, max_length=10)
    oracle: CaseOracle
    cleanup: dict | None = None
    side_effects: bool = False
    repetitions: int = Field(default=1, ge=1, le=20)
    observation_mode: Literal["external_observation", "instrumented_observation"] = "external_observation"

    @model_validator(mode="after")
    def distinct_controls(self):
        # The supervisor tells a control from the case it proves, and controls apart, by method, path and identity.
        keys = [(self.method, self.path, self.identity)] + [(c.method, c.path, c.identity) for c in self.preconditions if not isinstance(c, str)]
        names = [c.name for c in self.preconditions if not isinstance(c, str)]
        if len(set(keys)) != len(keys) or len(set(names)) != len(names):
            raise ValueError("Each positive control needs its own name and a request different from its case and other controls")
        return self


class CaseDesignProposal(Contract):
    cases: list[CaseProposal] = Field(default_factory=list, max_length=100)
    gaps: list[str] = Field(default_factory=list, max_length=200)


class OperatorControl(CaseControl):
    model_config = ConfigDict(extra="allow")
    required_text: list[Annotated[str, Field(min_length=1)]] = Field(min_length=1, max_length=20)


class OperatorOracle(CaseOracle):
    forbidden_text: list[str] = Field(default_factory=list, max_length=20)


class OperatorCase(CaseProposal):
    """Operator and retest cases may use any adapter or method and keep the sealed fields they were copied with."""
    model_config = ConfigDict(extra="allow")
    # Wider than the model contract on purpose; pydantic validates each class by its own annotations.
    adapter: Literal["http", "ai_http", "demo", "fixture", "zap", "schemathesis", "playwright", "promptfoo", "pyrit"]  # type: ignore[assignment]
    method: Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"] = "GET"  # type: ignore[assignment]
    preconditions: list[str | OperatorControl] = Field(default_factory=list, max_length=10)  # type: ignore[assignment]
    oracle: OperatorOracle


class ReportOrderProposal(Contract):
    finding_ids: list[str] = Field(default_factory=list, max_length=5000)


class CommanderProposal(Contract):
    reviewer_order: list[str] = Field(min_length=3, max_length=3)
    # Model-derived additions to the core questions: short, and passed on only as labelled untrusted data.
    focus: list[Annotated[str, Field(max_length=300)]] = Field(default_factory=list, max_length=30)
    rationale: str = Field(min_length=1, max_length=3000)


MIN_QUOTE_CHARACTERS = 6


def _verified_reference(raw: dict, files: dict) -> SourceReference:
    ref = SourceReference.model_validate(raw)
    if ref.file not in files:
        raise ValueError("Evidence cites a file outside the frozen snapshot")
    # A few characters occur on almost any line, so a quote must carry enough text to locate its claim.
    if len("".join(ref.quote.split())) < MIN_QUOTE_CHARACTERS:
        raise ValueError("Evidence quote is too short to locate its claim")
    lines = files[ref.file].splitlines()
    quoted_lines = ref.quote.splitlines()
    start = ref.line - 1
    if start >= len(lines) or "\n".join(lines[start:start + len(quoted_lines)]).find(ref.quote) == -1:
        raise ValueError("Evidence quote does not match its snapshot location")
    return ref


def verify_source_references(references: list[dict], source: dict) -> None:
    files = {item["path"]: item["content"] for item in source["files"]}
    for raw in references:
        _verified_reference(raw, files)


def partition_source_references(references: list[dict], source: dict) -> tuple[list[dict], list[str]]:
    """Keep the references that match the frozen snapshot and say why each other one was dropped."""
    files = {item["path"]: item["content"] for item in source["files"]}
    kept, dropped = [], []
    for raw in references:
        try:
            kept.append(_verified_reference(raw, files).model_dump())
        except ValueError as exc:
            dropped.append(str(exc).splitlines()[0])
    return kept, dropped


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
