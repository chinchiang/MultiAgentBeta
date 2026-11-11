from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator, model_validator
from .request_rules import HTTP_METHODS, RequestRefused, check_request, model_header_list_error
from .adapters import RESERVED_ENV, format_origin, parse_origin, target_ip_refused
from .contracts import OperatorCase, SecurityRequirement


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def origin(url: str) -> str:
    """The target's origin text, always with its port; the exact-origin rule (no path) is applied at preflight."""
    try:
        return format_origin(*parse_origin(url, allow_path=True))
    except ValueError:
        raise ValueError("An explicit HTTP(S) origin without userinfo is required") from None


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Budget(StrictModel):
    max_seconds: int = Field(default=600, ge=10, le=14400)
    max_requests: int = Field(default=30, ge=1, le=10000)
    max_model_calls: int = Field(default=20, ge=1, le=500)
    max_tokens: int = Field(default=50000, ge=1000, le=2000000)


class ModelProfile(StrictModel):
    id: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    role: Literal["commander", "reviewer", "architecture_mapper", "challenger", "threat_modeler", "test_designer", "reporter", "fallback"]
    provider: Literal["demo", "openai", "anthropic", "nvidia_nim", "openai_compatible", "bedrock"]
    model_id: str = Field(min_length=1, max_length=200)
    family: str = Field(min_length=1, max_length=100)
    endpoint: str = ""
    credential_env: str = ""
    # Bedrock signs each request with the operator's AWS profile (for example an SSO login) instead of a key.
    aws_profile: str = Field(default="", max_length=128, pattern=r"^[A-Za-z0-9_.@+-]*$")
    # How the endpoint is asked for JSON: json_object, or json_schema for servers that accept only a schema (LM Studio).
    json_mode: Literal["json_object", "json_schema"] = "json_object"
    # None leaves the model's own default, which some reasoning models require.
    temperature: float | None = Field(default=0, ge=0, le=2)
    max_output_tokens: int = Field(default=3000, ge=256, le=32768)
    timeout_seconds: int = Field(default=60, ge=5, le=1800)
    prompt_version: str = Field(default="v2", min_length=1, max_length=80)
    # A fallback Agent answers for the Agents named here when one of them refuses or is truncated, and for no other failure.
    fallback_for: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("credential_env")
    @classmethod
    def credential(cls, value):
        if value and not re.fullmatch(r"VIBEAUDIT_[A-Z0-9_]+", value):
            raise ValueError("Credentials must reference a VIBEAUDIT_* environment variable")
        if value in RESERVED_ENV:
            raise ValueError("Credentials cannot reference a Vibe Audit setting such as the database URL or session token")
        return value

    @model_validator(mode="after")
    def aws_signing(self):
        if self.provider == "bedrock" and (not self.aws_profile or self.credential_env):
            raise ValueError("A Bedrock model names an AWS profile and no credential variable")
        if self.provider != "bedrock" and self.aws_profile:
            raise ValueError("Only a Bedrock model uses an AWS profile")
        if (self.role == "fallback") != bool(self.fallback_for):
            raise ValueError("A fallback Agent names the Agents it stands in for, and only a fallback Agent does")
        return self


class AuthProfile(StrictModel):
    id: str
    credential_env: str
    header: str = "Authorization"
    scheme: str = "Bearer"
    role: str = ""
    # Model-designed cases may send only identities the operator opted in, so an injected or mistaken
    # case cannot pick a privileged account. Operator-written cases may use any configured identity.
    model_selectable: bool = False

    @field_validator("credential_env")
    @classmethod
    def credential(cls, value):
        return ModelProfile.credential(value)


StaticTool = Literal["semgrep", "osv", "gitleaks"]
STATIC_TOOLS: tuple[StaticTool, ...] = ("semgrep", "osv", "gitleaks")


# What run input says when a scope entry breaks the method and path grammar (request_rules.check_request). Like every
# other run input error it reaches the operator inside pydantic's validation error, not through the message table, so
# it is not one of the *_REFUSALS tables tests/test_error_messages.py holds to Chinese wording.
SCOPE_GRAMMAR_ERRORS = {
    "path": "Scope requires an exact relative HTTP path",
    "path_ascii": "Scope requires an exact relative HTTP path",
    "method": "Scope requires an explicit HTTP method",
}


class ScopeEntry(StrictModel):
    """One method and exact path of the operator's run scope, and what a model-written request to it may carry."""
    method: str = Field(json_schema_extra={"enum": list(HTTP_METHODS)})
    path: str
    model_body: bool = False
    model_headers: dict[str, list[str]] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def as_the_transport_reads_it(cls, value):
        # Checked before the field types, so each refusal keeps the words run input has always used.
        if not isinstance(value, dict) or set(value)-{"method","path","model_body","model_headers"} or not isinstance(value.get("model_body",False),bool):
            raise ValueError("Scope requires an exact relative HTTP path")
        # The path and method are held to the transport's own grammar: a scope entry no request could ever be sent
        # to is refused here, and the operator writes every method out.
        try:
            check_request(value,explicit_method=True)
        except RequestRefused as refused:
            raise ValueError(SCOPE_GRAMMAR_ERRORS[refused.rule]) from None
        if "model_headers" in value:
            problem=model_header_list_error(value["model_headers"])
            if problem:
                raise ValueError(problem)
        return value


class RunInput(StrictModel):
    schema_version: Literal[2] = 2
    name: str = Field(default="Security review", min_length=1, max_length=160)
    mode: Literal["demo", "live"] = "demo"
    source_path: str = ""
    deployment_id: str = ""
    target_url: str = ""
    data_policy: Literal["local_only", "cloud_allowed"] = "local_only"
    allowed_model_origins: list[str] = Field(default_factory=list)
    allowed_target_ips: list[str] = Field(default_factory=list)
    allowed_requests: list[ScopeEntry] = Field(default_factory=list, max_length=100)
    budget: Budget = Field(default_factory=Budget)
    models: list[ModelProfile] = Field(default_factory=list)
    auth_profiles: list[AuthProfile] = Field(default_factory=list)
    notes: str = Field(default="", max_length=10000)
    parent_run_id: str | None = None
    parent_finding_ids: list[str] = Field(default_factory=list, max_length=100)
    requirements: list[SecurityRequirement] = Field(default_factory=list, max_length=500)
    static_tools: list[StaticTool] = Field(default_factory=lambda: list(STATIC_TOOLS))
    runtime_profile: str = Field(default="default", pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    fixture_profile: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    deployment_header: str | None = Field(default=None, pattern=r"^[A-Za-z0-9-]{1,100}$")
    cases: list[dict] = Field(default_factory=list, max_length=100)
    # Exact strings the operator declares synthetic test credentials, so the source snapshot leaves them readable.
    unredacted_literals: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("unredacted_literals")
    @classmethod
    def test_literals(cls, value):
        if any(len(item) < 6 or len(item) > 200 or not item.isprintable() or item != item.strip() for item in value):
            raise ValueError("Unredacted test literals are exact single-line strings of 6 to 200 characters without surrounding spaces")
        return list(dict.fromkeys(value))

    @field_validator("allowed_target_ips")
    @classmethod
    def target_ips(cls, value):
        for item in value:
            try:
                address = ipaddress.ip_address(item)
            except ValueError:
                raise ValueError("Allowed target IPs must be explicit IP addresses, not hostnames or ranges") from None
            if target_ip_refused(address):
                raise ValueError("Target IPs cannot be cloud metadata, link-local, unspecified or multicast addresses")
        return value

    @field_validator("cases")
    @classmethod
    def supplied_cases(cls, value):
        # Checked before any paid stage, so a malformed case cannot fail the run after a request is sent.
        for case in value:
            # Strict JSON validation: a "5" is not a repetition count and a list is not a header map.
            OperatorCase.model_validate_json(json.dumps(case, allow_nan=False), strict=True)
        return value

    @field_validator("requirements")
    @classmethod
    def supplied_requirements(cls, value):
        # Whoever submits the run states these, so none is model-derived; the threat gate then insists each is mapped.
        return [r.model_copy(update={"source_kind": "operator"}) if r.source_kind == "derived" else r for r in value]

    @field_serializer("allowed_requests")
    def scope_as_written(self, scope):
        # The manifest holds each entry as the operator wrote it: a default left out would change it and its hash.
        return [entry.model_dump(exclude_unset=True) for entry in scope]

    @model_validator(mode="after")
    def validate_live(self):
        if self.parent_finding_ids and not self.parent_run_id:
            raise ValueError("Retested findings need the parent run they belong to")
        ids = [p.id for p in self.models]
        if len(ids) != len(set(ids)):
            raise ValueError("Agent IDs must be unique")
        auth_ids = [p.id for p in self.auth_profiles]
        if len(auth_ids) != len(set(auth_ids)):
            raise ValueError("Test identity IDs must be unique")
        # Values are compared at preflight, when the environment is read; names can be refused now.
        if {p.credential_env for p in self.models if p.credential_env} & {p.credential_env for p in self.auth_profiles}:
            raise ValueError("A credential cannot serve both a model and a test identity")
        primaries = {p.id: p for p in self.models if p.role != "fallback"}
        covered = [agent_id for p in self.models for agent_id in p.fallback_for]
        if any(agent_id not in primaries for agent_id in covered):
            raise ValueError("A fallback stands in only for configured Agents that are not fallbacks themselves")
        if len(covered) != len(set(covered)):
            raise ValueError("Each Agent can have only one fallback")
        for fallback in (p for p in self.models if p.role == "fallback"):
            for agent_id in fallback.fallback_for:
                primary = primaries[agent_id]
                if (fallback.provider, fallback.model_id, fallback.endpoint) == (primary.provider, primary.model_id, primary.endpoint):
                    raise ValueError("A fallback must be a different model configuration from the Agent it stands in for")
                # The whitebox gate needs three families; a fallback that repeats another reviewer's could never pass it.
                if primary.role == "reviewer" and fallback.family.casefold() in {p.family.casefold() for p in primaries.values() if p.role == "reviewer" and p.id != agent_id}:
                    raise ValueError("A reviewer's fallback must be a model family none of the other reviewers use")
        if self.mode == "live":
            if "budget" not in self.model_fields_set:
                raise ValueError("Live runs require an explicit request, time and model-usage budget")
            if not self.source_path or not self.target_url or not self.allowed_target_ips:
                raise ValueError("Live mode requires source_path, target_url and explicit allowed_target_ips")
            origin(self.target_url)
            reviewers = [p for p in self.models if p.role == "reviewer"]
            if len(reviewers) != 3 or len([p for p in self.models if p.role == "commander"]) != 1:
                raise ValueError("Live mode requires exactly one commander and three reviewers")
            if len({(p.provider, p.model_id, p.endpoint) for p in reviewers}) != 3 or len({p.family.casefold() for p in reviewers}) != 3:
                raise ValueError("Three distinct model configurations and declared families are required")
            if any(p.provider == "demo" for p in self.models):
                raise ValueError("Synthetic providers cannot be used in live runs")
            if any(not p.endpoint for p in self.models):
                raise ValueError("Every live model requires an explicit endpoint")
            dedicated=[p.role for p in self.models if p.role not in {"reviewer","commander","fallback"}]
            if len(dedicated)!=len(set(dedicated)):
                raise ValueError("Each dedicated logical role can have only one configured Agent")
        return self


def demo_profiles() -> list[dict]:
    return [dict(id=id_, role=role, provider="demo", model_id="synthetic-" + family,
                 family=family, endpoint="", credential_env="", temperature=0, max_output_tokens=3000)
            for id_, role, family in [("commander", "commander", "planner"), ("reviewer-a", "reviewer", "alpha"),
                                      ("reviewer-b", "reviewer", "beta"), ("reviewer-c", "reviewer", "gamma")]]


def new_run(run_id: str, data: RunInput) -> dict:
    manifest = data.model_dump()
    if data.mode == "demo":
        manifest["models"] = demo_profiles()
    return dict(id=run_id, name=data.name, mode=data.mode, status="created", stage="intake", created_at=now(),
                updated_at=now(), manifest=manifest, manifest_hash=digest(manifest), events=[], reviews=[],
                threat_model=None, cases=[], executions=[], findings=[], gaps=[], limitations=[], usage={"requests":0,"model_calls":0,"tokens":0},
                artifacts=[], error=None, source_digest="", gate_receipts={}, started_at=None, model_probes=[])
