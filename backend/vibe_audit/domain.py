from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from .adapters import RESERVED_ENV, target_ip_refused
from .contracts import OperatorCase, SecurityRequirement


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def origin(url: str) -> str:
    p = urlsplit(url)
    if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
        raise ValueError("An explicit HTTP(S) origin without userinfo is required")
    host = f"[{p.hostname}]" if ":" in p.hostname else p.hostname
    return f"{p.scheme}://{host}:{p.port or (443 if p.scheme == 'https' else 80)}"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Budget(StrictModel):
    max_seconds: int = Field(default=600, ge=10, le=14400)
    max_requests: int = Field(default=30, ge=1, le=10000)
    max_model_calls: int = Field(default=20, ge=1, le=500)
    max_tokens: int = Field(default=50000, ge=1000, le=2000000)


class ModelProfile(StrictModel):
    id: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    role: Literal["commander", "reviewer", "architecture_mapper", "challenger", "threat_modeler", "test_designer", "reporter"]
    provider: Literal["demo", "openai", "anthropic", "nvidia_nim", "openai_compatible"]
    model_id: str = Field(min_length=1, max_length=200)
    family: str = Field(min_length=1, max_length=100)
    endpoint: str = ""
    credential_env: str = ""
    # None leaves the model's own default, which some reasoning models require.
    temperature: float | None = Field(default=0, ge=0, le=2)
    max_output_tokens: int = Field(default=3000, ge=256, le=16000)
    timeout_seconds: int = Field(default=60, ge=5, le=300)
    prompt_version: str = Field(default="v2", min_length=1, max_length=80)

    @field_validator("credential_env")
    @classmethod
    def credential(cls, value):
        if value and not re.fullmatch(r"VIBEAUDIT_[A-Z0-9_]+", value):
            raise ValueError("Credentials must reference a VIBEAUDIT_* environment variable")
        if value in RESERVED_ENV:
            raise ValueError("Credentials cannot reference a Vibe Audit setting such as the database URL or session token")
        return value


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
    allowed_requests: list[dict] = Field(default_factory=list, max_length=100)
    budget: Budget = Field(default_factory=Budget)
    models: list[ModelProfile] = Field(default_factory=list)
    auth_profiles: list[AuthProfile] = Field(default_factory=list)
    notes: str = Field(default="", max_length=10000)
    parent_run_id: str | None = None
    parent_finding_ids: list[str] = Field(default_factory=list, max_length=100)
    requirements: list[SecurityRequirement] = Field(default_factory=list, max_length=500)
    static_tools: list[Literal["semgrep", "osv", "gitleaks"]] = Field(default_factory=lambda:["semgrep", "osv", "gitleaks"])
    runtime_profile: str = Field(default="default", pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    fixture_profile: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    deployment_header: str | None = Field(default=None, pattern=r"^[A-Za-z0-9-]{1,100}$")
    cases: list[dict] = Field(default_factory=list, max_length=100)

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

    @model_validator(mode="after")
    def validate_live(self):
        ids = [p.id for p in self.models]
        if len(ids) != len(set(ids)):
            raise ValueError("Agent IDs must be unique")
        auth_ids = [p.id for p in self.auth_profiles]
        if len(auth_ids) != len(set(auth_ids)):
            raise ValueError("Test identity IDs must be unique")
        # Values are compared at preflight, when the environment is read; names can be refused now.
        if {p.credential_env for p in self.models if p.credential_env} & {p.credential_env for p in self.auth_profiles}:
            raise ValueError("A credential cannot serve both a model and a test identity")
        for request in self.allowed_requests:
            if set(request)-{"method","path","model_body"} or not isinstance(request.get("model_body",False),bool) or not isinstance(request.get("path"),str) or not request["path"].startswith("/") or request["path"].startswith("//") or any(c in request["path"] for c in "\r\n\\"):
                raise ValueError("Scope requires an exact relative HTTP path")
            if request.get("method") not in {"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"}:
                raise ValueError("Scope requires an explicit HTTP method")
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
            dedicated=[p.role for p in self.models if p.role not in {"reviewer","commander"}]
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
