from __future__ import annotations

import time
from datetime import datetime, timezone

from .request_rules import RequestRefused, plan_case
from .domain import digest


# What the case gate says when a case breaks a request rule (request_rules.plan_case).
GATE_REFUSALS={
    "headers":"Case headers cannot carry credentials, relay controls or method/path overrides; a model-designed header must be one the operator listed in allowed_requests[].model_headers for that method and path",
    "identity":"A model-designed case can use only test identities the operator marked as model-selectable",
    "scope":"Case or fixture request exceeds the declared method/path scope",
}


class PolicyError(RuntimeError):
    pass


def sealed(value: dict) -> str:
    return digest({k:v for k,v in value.items() if k != "hash"})


def elapsed_seconds(run: dict) -> float:
    """Active time across attempts; the gap between an interruption and its resume spends no budget."""
    total = run.get("active_seconds", 0)
    if run.get("attempt_started_at"):
        total += (datetime.now(timezone.utc)-datetime.fromisoformat(run["attempt_started_at"])).total_seconds()
    return total


class Policy:
    def __init__(self):
        self.receipts = {}
        self.catalog = None

    def catalog_manifest(self):
        # A CatalogError names the file that failed, so it reaches the run as it is.
        from .catalog import load_catalogs
        if self.catalog is None:
            self.catalog=load_catalogs()
        return self.catalog.manifest()

    def standards(self, ids, manifest=None):
        from .catalog import load_catalogs,CatalogError
        try:
            if self.catalog is None:
                self.catalog=load_catalogs()
            if manifest is not None and digest(manifest)!=digest(self.catalog.manifest()):
                raise PolicyError("Catalog version differs from the run's frozen reference data")
            return self.catalog.validate_ids(ids)
        except CatalogError as exc:
            raise PolicyError("Unrecognized, unversioned or unverifiable standard reference") from exc

    def assert_manifest(self, run):
        if digest(run["manifest"]) != run["manifest_hash"]:
            raise PolicyError("Run scope or model configuration changed; create a new run")

    def whitebox_gate(self, run):
        self.assert_manifest(run)
        expected = {p["id"] for p in run["manifest"]["models"] if p["role"]=="reviewer"}
        reviews = run["reviews"]
        if len(expected)!=3 or {r["agent_id"] for r in reviews}!=expected or len(reviews)!=3:
            raise PolicyError("Three independent reviewers are required")
        if any(r["status"]!="completed" or r["input_hash"]!=run["source_digest"] for r in reviews):
            raise PolicyError("Incomplete review or source mismatch")
        if len({r["family"].casefold() for r in reviews})!=3:
            raise PolicyError("Model family diversity incomplete")
        if run["mode"]=="live" and any(r.get("simulated") for r in reviews):
            raise PolicyError("Synthetic reviews are not live evidence")
        run["gate_receipts"]["whitebox"] = digest(reviews)

    def threat_gate(self, run):
        self.whitebox_gate(run)
        tm=run.get("threat_model")
        if not tm or tm.get("source_digest")!=run["source_digest"] or tm.get("deployment_id")!=run["manifest"]["deployment_id"]:
            raise PolicyError("Missing or stale threat model")
        if not tm.get("assets") or not tm.get("dataflows") or not tm.get("threats"):
            raise PolicyError("Threat model requires assets, dataflows and threats")
        if tm.get("hash")!=sealed(tm):
            raise PolicyError("Threat model hash mismatch")
        self.standards(tm.get("standards",[]),run.get("catalog_manifest"))
        assets={a["id"] for a in tm["assets"]}
        requirements={r["id"]:r for r in tm.get("requirements",[])}
        if not requirements or len(requirements)!=len(tm["requirements"]):
            raise PolicyError("Threat model requires unique security requirement objects")
        for requirement in requirements.values():
            self.standards(requirement.get("standard_ids",[]))  # the catalog version was checked once above
            if not requirement.get("statement") or not requirement.get("source"):
                raise PolicyError("Security requirement lacks statement or provenance")
        tids=set()
        for flow in tm["dataflows"]:
            if flow.get("source") not in assets or flow.get("target") not in assets or not flow.get("boundary"):
                raise PolicyError("Dataflow has invalid endpoints or missing trust boundary")
        for threat in tm["threats"]:
            if threat.get("id") in tids or not all(threat.get(k) for k in ("id","title","category","invariant","impact","requirement_id","asset_ids")):
                raise PolicyError("Incomplete or duplicate threat")
            tids.add(threat["id"])
            if threat["requirement_id"] not in requirements or threat["id"] not in requirements[threat["requirement_id"]]["threat_ids"]:
                raise PolicyError("Threat-to-requirement traceability is broken")
            if not set(threat["asset_ids"])<=assets:
                raise PolicyError("Threat references unknown asset")
            if threat.get("testability") not in {"automated","blocked"}:
                raise PolicyError("Threat testability missing")
            if threat["testability"]=="blocked" and not threat.get("blocked_reason"):
                raise PolicyError("Untestable threat needs a reason")
        for requirement in requirements.values():
            if not set(requirement.get("threat_ids",[]))<=tids:
                raise PolicyError("Security requirement references an unknown threat")
            if requirement.get("source_kind") in {"operator","specification"} and not requirement.get("threat_ids"):
                raise PolicyError("Operator security requirement has not been mapped to a threat")
        run["gate_receipts"]["threat_model"] = tm["hash"]

    def case_gate(self, run):
        self.threat_gate(run)
        tm=run["threat_model"]
        threats={t["id"]:t for t in tm["threats"]}
        seen=set()
        covered=set()
        for case in run["cases"]:
            if not case.get("id") or case["id"] in seen:
                raise PolicyError("Missing or duplicate case ID")
            seen.add(case["id"])
            tids=set(case.get("threat_ids",[]))
            if not tids or not tids<=threats.keys():
                raise PolicyError("Case threat traceability is broken")
            if any(case.get("requirement_id")!=threats[t]["requirement_id"] for t in tids):
                raise PolicyError("Case security requirement mismatch")
            if case.get("source_digest")!=run["source_digest"] or case.get("threat_model_hash")!=tm["hash"] or case.get("hash")!=sealed(case):
                raise PolicyError("Case is stale or has been modified")
            oracle=case.get("oracle",{})
            if oracle.get("kind") not in {"deny_sensitive","canary_absent","no_unauthorized_commit"} or not oracle.get("required_observations"):
                raise PolicyError("Case needs an executable oracle and observation requirements")
            if oracle["kind"] in {"deny_sensitive","canary_absent"} and not oracle.get("forbidden_text"):
                raise PolicyError("Content oracle requires explicit forbidden values")
            if case.get("side_effects") and not case.get("cleanup"):
                raise PolicyError("State-changing test requires an explicit cleanup plan")
            if case.get("adapter") not in {"http","ai_http","demo","fixture","zap","schemathesis","playwright","promptfoo","pyrit"} or (run["mode"]=="live" and case["adapter"]=="demo"):
                raise PolicyError("Unavailable adapter")
            if case.get("observation_mode") not in {"external_observation","instrumented_observation"}:
                raise PolicyError("Observation mode is required")
            if not 1<=case.get("repetitions",1)<=20:
                raise PolicyError("Invalid repetition count")
            # The request rules decide every request the case may send: its headers, identities and scope.
            try:
                plan_case(run["manifest"],case,live=run["mode"]=="live")
            except RequestRefused as refused:
                raise PolicyError(GATE_REFUSALS[refused.rule]) from None
            if run["mode"]=="live":
                if case.get("fixture_profile"):
                    from .fixture_protocol import fixture_profile_hash
                    if case.get("fixture_profile_hash")!=fixture_profile_hash(case["fixture_profile"]):
                        raise PolicyError("Trusted fixture configuration changed after case sealing")
            covered|=tids
        missing={t for t,v in threats.items() if v["testability"]=="automated"}-covered
        if missing and not run["cases"] and not run["manifest"].get("cases"):
            raise PolicyError("Automated threats without cases: "+", ".join(sorted(missing)))
        if missing:
            # The operator chose these cases, or the test designer found no single sealed request that shows the rest
            # (real models do this with threats that need a forged Host or a session): either way the threats left
            # out stay visible as untested and the run cannot read as complete.
            label=("Automated threats without a provided case were not tested" if run["manifest"].get("cases")
                   else "Automated threats without a model-designed case were not tested")
            gap=label+": "+", ".join(sorted(missing))
            if gap not in run["gaps"]:
                run["gaps"].append(gap)
        receipt=digest([c["hash"] for c in run["cases"]])
        run["gate_receipts"]["cases"]=receipt
        self.receipts[run["id"]]=(run["manifest_hash"],tm["hash"],receipt, time.monotonic()+run["manifest"]["budget"]["max_seconds"])

    def authorize(self, run, case, cancel_event, *, method=None, path=None, identity=None):
        self.assert_manifest(run)
        if cancel_event.is_set() or run["status"]!="running" or run["stage"]!="blackbox":
            raise PolicyError("Execution is cancelled or outside black-box stage")
        receipt=self.receipts.get(run["id"])
        if not receipt or time.monotonic()>receipt[3]:
            raise PolicyError("Missing or expired execution capability")
        if receipt[:3] != (run["manifest_hash"],sealed(run["threat_model"]),digest([c["hash"] for c in run["cases"]])):
            raise PolicyError("Execution capability no longer matches approved artifacts")
        approved=next((c for c in run["cases"] if c["id"]==case["id"]),None)
        if not approved or case.get("hash")!=sealed(case) or sealed(approved)!=case["hash"]:
            raise PolicyError("Unapproved case")
        # The capability itself carries the operator's approval, not only the engine's stage order.
        if run["mode"]=="live" and case.get("designed_by")=="model" and (run.get("case_approval") or {}).get("receipt")!=receipt[2]:
            raise PolicyError("Model-designed cases need the operator's approval of this sealed case set")
        if run["mode"]=="live":
            requested=((method or case.get("method","GET")).upper(),path or case.get("path"))
            allowed={(r.get("method","GET").upper(),r.get("path")) for r in run["manifest"].get("allowed_requests",[])}
            if requested not in allowed:
                raise PolicyError("Request method and exact path were not authorized in run scope")
            permitted={(case.get("method","GET").upper(),case.get("path"))}
            permitted|={(p.get("method","GET").upper(),p.get("path")) for p in case.get("preconditions",[]) if isinstance(p,dict)}
            # A fixture case's lifecycle steps are the allowed_requests the engine sealed into it. An operator case's own
            # steps, setup, reset or cleanup fields are sent by no executor, so they permit nothing.
            permitted|={(s.get("method","GET").upper(),s.get("path")) for s in case.get("allowed_requests",[]) if isinstance(s,dict)}
            if requested not in permitted:
                raise PolicyError("Request is not a step in the sealed test case")
            allowed_identities={case.get("identity")}
            allowed_identities|={p.get("identity") for p in case.get("preconditions",[]) if isinstance(p,dict)}
            allowed_identities|={p.get("identity") for p in case.get("allowed_requests",[]) if isinstance(p,dict)}
            if identity not in allowed_identities:
                raise PolicyError("Identity is outside the sealed case scope")
        if run["usage"]["requests"]>=run["manifest"]["budget"]["max_requests"]:
            raise PolicyError("Request budget exhausted")
        if elapsed_seconds(run)>=run["manifest"]["budget"]["max_seconds"]:
            raise PolicyError("Run time budget exhausted")
        run["usage"]["requests"]+=1

    def revoke(self, run_id):
        self.receipts.pop(run_id,None)
