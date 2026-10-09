"""Each check of the deterministic gates, exercised directly on the stored demo run (docs/sample-report.json).

The engine tests drive the gates through whole runs; these name every refusal and the exact condition behind it,
so a loosened comparison, a dropped clause or a renamed field fails here in seconds.
"""
import copy
import json
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vibe_audit.catalog import load_catalogs
from vibe_audit.domain import digest
from vibe_audit.policy import Policy, PolicyError, elapsed_seconds, sealed

ROOT = Path(__file__).resolve().parents[1]
DEMO = json.loads((ROOT / "docs" / "sample-report.json").read_text(encoding="utf-8"))
HEADER_RULE = "Case headers cannot carry credentials, relay controls or method/path overrides"


@pytest.fixture
def run():
    record = copy.deepcopy(DEMO)
    record["gate_receipts"] = {}
    record["catalog_manifest"] = load_catalogs().manifest()
    return record


def rehash_manifest(record):
    record["manifest_hash"] = digest(record["manifest"])


def reseal(record):
    """Seal the threat model and cases again after a deliberate change, so only the changed rule is under test."""
    tm = record["threat_model"]
    tm["hash"] = sealed(tm)
    for case in record["cases"]:
        case["threat_model_hash"] = tm["hash"]
        case["hash"] = sealed(case)


def live(record):
    """The demo run as a live run: real adapters, non-synthetic reviews and a declared request scope."""
    record["mode"] = "live"
    for review in record["reviews"]:
        review["simulated"] = False
    record["manifest"]["allowed_requests"] = [{"method": "GET", "path": "/orders/private"}]
    rehash_manifest(record)
    for case in record["cases"]:
        case["adapter"] = "http"
    reseal(record)
    return record


def refused(gate, record, message):
    with pytest.raises(PolicyError, match="^" + re.escape(message)):
        gate(record)


def test_sealed_ignores_the_hash_field_and_elapsed_time_adds_the_running_attempt():
    assert sealed({"a": 1, "hash": "x"}) == sealed({"a": 1}) == digest({"a": 1})
    assert elapsed_seconds({}) == 0 and elapsed_seconds({"active_seconds": 7}) == 7
    started = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
    assert 36 <= elapsed_seconds({"active_seconds": 7, "attempt_started_at": started}) < 40


def test_whitebox_gate_names_each_refusal(run):
    policy = Policy()
    policy.whitebox_gate(run)
    assert run["gate_receipts"]["whitebox"] == digest(run["reviews"])

    changed = copy.deepcopy(run); changed["manifest"]["notes"] = "edited after sealing"
    refused(policy.whitebox_gate, changed, "Run scope or model configuration changed; create a new run")

    fewer = copy.deepcopy(run); fewer["reviews"].pop()
    refused(policy.whitebox_gate, fewer, "Three independent reviewers are required")
    repeated = copy.deepcopy(run); repeated["reviews"][1]["agent_id"] = repeated["reviews"][0]["agent_id"]
    refused(policy.whitebox_gate, repeated, "Three independent reviewers are required")
    fourth = copy.deepcopy(run); fourth["manifest"]["models"].append({**fourth["manifest"]["models"][1], "id": "reviewer-d"}); rehash_manifest(fourth)
    refused(policy.whitebox_gate, fourth, "Three independent reviewers are required")
    extra = copy.deepcopy(run); extra["reviews"].append({**extra["reviews"][0]})
    refused(policy.whitebox_gate, extra, "Three independent reviewers are required")

    unfinished = copy.deepcopy(run); unfinished["reviews"][2]["status"] = "failed"
    refused(policy.whitebox_gate, unfinished, "Incomplete review or source mismatch")
    other_source = copy.deepcopy(run); other_source["reviews"][0]["input_hash"] = digest("other")
    refused(policy.whitebox_gate, other_source, "Incomplete review or source mismatch")

    # Family names that differ only in letter case are one family.
    same_family = copy.deepcopy(run); same_family["reviews"][1]["family"] = run["reviews"][0]["family"].upper()
    refused(policy.whitebox_gate, same_family, "Model family diversity incomplete")

    synthetic = copy.deepcopy(run); synthetic["mode"] = "live"
    refused(policy.whitebox_gate, synthetic, "Synthetic reviews are not live evidence")
    policy.whitebox_gate(live(copy.deepcopy(run)))


def test_threat_gate_names_each_refusal(run):
    policy = Policy()
    policy.threat_gate(run)
    assert run["gate_receipts"]["threat_model"] == run["threat_model"]["hash"] == sealed(run["threat_model"])

    def broken(change, message, seal=True):
        record = copy.deepcopy(run)
        change(record, record["threat_model"])
        if seal:
            reseal(record)
        refused(policy.threat_gate, record, message)

    broken(lambda r, tm: r.update(threat_model=None), "Missing or stale threat model", seal=False)
    broken(lambda r, tm: tm.update(source_digest=digest("other")), "Missing or stale threat model")
    broken(lambda r, tm: tm.update(deployment_id="v2"), "Missing or stale threat model")
    for key in ("assets", "dataflows", "threats"):
        broken(lambda r, tm, key=key: tm.update({key: []}), "Threat model requires assets, dataflows and threats")
    broken(lambda r, tm: tm.update(hash="0" * 64), "Threat model hash mismatch", seal=False)
    broken(lambda r, tm: tm.update(standards=["NOPE-1"]), "Unrecognized, unversioned or unverifiable standard reference")
    broken(lambda r, tm: r.update(catalog_manifest={"schema_version": 1}), "Catalog version differs from the run's frozen reference data")
    broken(lambda r, tm: tm.update(requirements=[]), "Threat model requires unique security requirement objects")
    broken(lambda r, tm: tm["requirements"].append(copy.deepcopy(tm["requirements"][0])), "Threat model requires unique security requirement objects")
    broken(lambda r, tm: tm["requirements"][0].update(standard_ids=["NOPE-1"]), "Unrecognized, unversioned or unverifiable standard reference")
    broken(lambda r, tm: tm["requirements"][0].update(statement=""), "Security requirement lacks statement or provenance")
    broken(lambda r, tm: tm["requirements"][0].update(source=None), "Security requirement lacks statement or provenance")
    broken(lambda r, tm: tm["dataflows"][0].update(source="ghost"), "Dataflow has invalid endpoints or missing trust boundary")
    broken(lambda r, tm: tm["dataflows"][0].update(target="ghost"), "Dataflow has invalid endpoints or missing trust boundary")
    broken(lambda r, tm: tm["dataflows"][0].update(boundary=""), "Dataflow has invalid endpoints or missing trust boundary")
    broken(lambda r, tm: tm["threats"][1].update(id=tm["threats"][0]["id"]), "Incomplete or duplicate threat")
    for key in ("id", "title", "category", "invariant", "impact", "requirement_id", "asset_ids"):
        broken(lambda r, tm, key=key: tm["threats"][0].update({key: ""}), "Incomplete or duplicate threat")
    broken(lambda r, tm: tm["threats"][0].update(requirement_id="R-999"), "Threat-to-requirement traceability is broken")
    broken(lambda r, tm: tm["requirements"][0].update(threat_ids=[]), "Threat-to-requirement traceability is broken")
    broken(lambda r, tm: tm["threats"][0].update(asset_ids=["orders", "ghost"]), "Threat references unknown asset")
    broken(lambda r, tm: tm["threats"][0].update(testability="manual"), "Threat testability missing")
    broken(lambda r, tm: tm["threats"][0].update(testability="blocked", blocked_reason=""), "Untestable threat needs a reason")
    broken(lambda r, tm: tm["requirements"][1].update(threat_ids=["T-002", "T-999"]), "Security requirement references an unknown threat")
    for kind in ("operator", "specification"):
        broken(lambda r, tm, kind=kind: tm["requirements"].append({"id": "R-OP", "statement": "s", "source": "operator", "source_kind": kind, "threat_ids": [], "standard_ids": []}),
               "Operator security requirement has not been mapped to a threat")

    # A blocked threat with its reason, and a derived requirement without threats, pass.
    record = copy.deepcopy(run)
    record["threat_model"]["threats"][1].update(testability="blocked", blocked_reason="needs a staging ledger")
    record["threat_model"]["requirements"].append({"id": "R-D", "statement": "s", "source": "model", "source_kind": "derived", "threat_ids": [], "standard_ids": []})
    reseal(record)
    policy.threat_gate(record)


def test_case_gate_names_each_refusal(run):
    policy = Policy()
    policy.case_gate(run)
    assert run["gate_receipts"]["cases"] == digest([c["hash"] for c in run["cases"]])
    assert policy.receipts[run["id"]][:3] == (run["manifest_hash"], run["threat_model"]["hash"], run["gate_receipts"]["cases"])

    def broken(change, message, seal=True, base=None):
        record = copy.deepcopy(base or run)
        change(record, record["cases"][0])
        if seal:
            reseal(record)
        refused(policy.case_gate, record, message)

    broken(lambda r, c: c.update(id=""), "Missing or duplicate case ID")
    broken(lambda r, c: r["cases"][1].update(id=c["id"]), "Missing or duplicate case ID")
    broken(lambda r, c: c.update(threat_ids=[]), "Case threat traceability is broken")
    broken(lambda r, c: c.update(threat_ids=["T-001", "T-999"]), "Case threat traceability is broken")
    broken(lambda r, c: c.update(requirement_id="R-002"), "Case security requirement mismatch")
    broken(lambda r, c: c.update(source_digest=digest("other"), hash=None) or c.update(hash=sealed(c)), "Case is stale or has been modified", seal=False)
    broken(lambda r, c: c.update(threat_model_hash="0" * 64) or c.update(hash=sealed(c)), "Case is stale or has been modified", seal=False)
    broken(lambda r, c: c.update(title="edited after sealing"), "Case is stale or has been modified", seal=False)
    broken(lambda r, c: c["oracle"].update(kind="vibes"), "Case needs an executable oracle and observation requirements")
    broken(lambda r, c: c["oracle"].update(required_observations=[]), "Case needs an executable oracle and observation requirements")
    for kind in ("deny_sensitive", "canary_absent"):
        broken(lambda r, c, kind=kind: c["oracle"].update(kind=kind, forbidden_text=[]), "Content oracle requires explicit forbidden values")
    broken(lambda r, c: c.update(side_effects=True, cleanup=None), "State-changing test requires an explicit cleanup plan")
    broken(lambda r, c: c.update(adapter="curl"), "Unavailable adapter")
    broken(lambda r, c: c.update(adapter="demo"), "Unavailable adapter", base=live(copy.deepcopy(run)))
    broken(lambda r, c: c.update(observation_mode="guess"), "Observation mode is required")
    for count in (0, 21):
        broken(lambda r, c, count=count: c.update(repetitions=count), "Invalid repetition count")
    broken(lambda r, c: c.update(headers={"Authorization": "Bearer x"}), HEADER_RULE)
    broken(lambda r, c: c["preconditions"].append({"method": "GET", "path": "/orders/private", "headers": {"Cookie": "a=b"}}), HEADER_RULE)
    # A model-designed header needs the operator's vocabulary for that method and path; the demo manifest lists none.
    broken(lambda r, c: c.update(designed_by="model", headers={"Accept": "text/html"}), HEADER_RULE)
    broken(lambda r, c: (r["manifest"].update(auth_profiles=[{"id": "alice", "model_selectable": False}]), rehash_manifest(r), c.update(designed_by="model", identity="alice")),
           "A model-designed case can use only test identities the operator marked as model-selectable")
    broken(lambda r, c: (r["manifest"].update(auth_profiles=[{"id": "alice", "model_selectable": True}]), rehash_manifest(r),
                         c.update(designed_by="model"), c["preconditions"].append({"method": "GET", "path": "/orders/private", "identity": "bob"})),
           "A model-designed case can use only test identities the operator marked as model-selectable")

    # Live runs must stay inside the declared request scope, preconditions and fixture requests included.
    as_live = live(copy.deepcopy(run))
    policy.case_gate(copy.deepcopy(as_live))
    broken(lambda r, c: c.update(path="/orders/all"), "Case or fixture request exceeds the declared method/path scope", base=as_live)
    broken(lambda r, c: c.update(method="DELETE"), "Case or fixture request exceeds the declared method/path scope", base=as_live)
    broken(lambda r, c: c["preconditions"].append({"method": "POST", "path": "/orders/private"}), "Case or fixture request exceeds the declared method/path scope", base=as_live)
    broken(lambda r, c: c.update(allowed_requests=[{"method": "GET", "path": "/admin"}]), "Case or fixture request exceeds the declared method/path scope", base=as_live)
    broken(lambda r, c: c.update(fixture_profile="synthetic-web-v1", fixture_profile_hash="stale"), "Trusted fixture configuration changed after case sealing", base=as_live)

    # An automated threat no case tests stops an engine-designed case set and is a recorded gap for an operator's.
    untested = copy.deepcopy(run); untested["cases"] = [c for c in untested["cases"] if "T-002" not in c["threat_ids"]]
    refused(policy.case_gate, untested, "Automated threats without cases: T-002")
    untested["manifest"]["cases"] = [{"id": "operator-chosen"}]; rehash_manifest(untested)
    policy.case_gate(untested); policy.case_gate(untested)
    assert untested["gaps"].count("Automated threats without a provided case were not tested: T-002") == 1


def test_authorize_checks_the_capability_scope_and_budget(run, monkeypatch):
    policy = Policy()
    policy.case_gate(run)
    run.update(status="running", stage="blackbox")
    run["usage"]["requests"] = 0
    case = run["cases"][0]
    idle = threading.Event()

    def refusal(message, record=run, event=idle, **kwargs):
        with pytest.raises(PolicyError, match="^" + re.escape(message)):
            policy.authorize(record, case, event, **kwargs)

    policy.authorize(run, case, idle)
    assert run["usage"]["requests"] == 1

    cancelled = threading.Event(); cancelled.set()
    refusal("Execution is cancelled or outside black-box stage", event=cancelled)
    for status, stage in (("cancelling", "blackbox"), ("running", "report")):
        refusal("Execution is cancelled or outside black-box stage", record={**run, "status": status, "stage": stage})
    changed = copy.deepcopy(run); changed["manifest"]["notes"] = "edited"
    refusal("Run scope or model configuration changed; create a new run", record=changed)

    receipt = policy.receipts[run["id"]]
    policy.receipts[run["id"]] = (*receipt[:3], time.monotonic() - 1)
    refusal("Missing or expired execution capability")
    policy.receipts[run["id"]] = (receipt[0], digest("other"), receipt[2], receipt[3])
    refusal("Execution capability no longer matches approved artifacts")
    policy.receipts[run["id"]] = receipt

    with pytest.raises(PolicyError, match="^Unapproved case"):
        policy.authorize(run, {**case, "id": "C-999"}, idle)
    with pytest.raises(PolicyError, match="^Unapproved case"):
        policy.authorize(run, {**case, "title": "edited"}, idle)
    with pytest.raises(PolicyError, match="^Unapproved case"):
        policy.authorize(run, {**case, "hash": "0" * 64}, idle)

    run["usage"]["requests"] = run["manifest"]["budget"]["max_requests"]
    refusal("Request budget exhausted")
    run["usage"]["requests"] = 0
    run["active_seconds"] = run["manifest"]["budget"]["max_seconds"]
    refusal("Run time budget exhausted")
    run["active_seconds"] = 0

    policy.revoke(run["id"])
    refusal("Missing or expired execution capability")
    policy.revoke("never-issued")


def test_authorize_in_a_live_run_binds_requests_to_the_sealed_case(run):
    policy = Policy()
    record = live(run)
    record["manifest"]["allowed_requests"] = [{"method": "GET", "path": "/orders/private"}, {"method": "GET", "path": "/orders/mine"},
                                              {"method": "POST", "path": "/reset"}, {"method": "GET", "path": "/admin"}]
    record["manifest"]["auth_profiles"] = [{"id": "alice", "model_selectable": True}, {"id": "bob", "model_selectable": True}]
    rehash_manifest(record)
    case = record["cases"][0]
    case.update(identity="alice", designed_by="model", steps=[{"method": "GET", "path": "/orders/mine"}], reset={"method": "POST", "path": "/reset"},
                allowed_requests=[{"method": "GET", "path": "/orders/private", "identity": "bob"}])
    reseal(record)
    policy.case_gate(record)
    record.update(status="running", stage="blackbox")
    record["usage"]["requests"] = 0
    idle = threading.Event()

    def refusal(message, **kwargs):
        with pytest.raises(PolicyError, match="^" + re.escape(message)):
            policy.authorize(record, case, idle, **kwargs)

    # A model-designed case needs the operator's approval of exactly this sealed case set.
    refusal("Model-designed cases need the operator's approval of this sealed case set", identity="alice")
    record["case_approval"] = {"receipt": "other"}
    refusal("Model-designed cases need the operator's approval of this sealed case set", identity="alice")
    record["case_approval"] = {"receipt": record["gate_receipts"]["cases"]}

    policy.authorize(record, case, idle, identity="alice")
    policy.authorize(record, case, idle, method="get", path="/orders/mine", identity="alice")
    policy.authorize(record, case, idle, method="POST", path="/reset", identity="alice")
    policy.authorize(record, case, idle, identity="bob")
    assert record["usage"]["requests"] == 4
    refusal("Request method and exact path were not authorized in run scope", method="GET", path="/orders/private/1", identity="alice")
    refusal("Request method and exact path were not authorized in run scope", method="DELETE", path="/orders/private", identity="alice")
    refusal("Request is not a step in the sealed test case", method="GET", path="/admin", identity="alice")
    refusal("Identity is outside the sealed case scope", identity="carol")
    refusal("Identity is outside the sealed case scope")
