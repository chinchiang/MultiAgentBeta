"""Boundaries added after the 2026-10-06 VibeSec G4 architecture and identity review."""
import base64
import json
import sys

import pytest

from vibe_audit import adapters
from vibe_audit.adapters import AdapterBlocked, _prepare_request, canonical_model_headers, case_headers_allowed

# Every value of the fixed model vocabulary that these tests use, as an operator would list it for an endpoint.
LISTED = {"accept": {"application/json", "text/html", "*/*"}, "accept-language": {"zh-TW"},
          "content-type": {"application/json; charset=utf-8", "application/json;charset=utf-8"},
          "if-none-match": {"*"}, "x-requested-with": {"XMLHttpRequest"}}
LISTED_MANIFEST = {"allowed_requests": [{"method": "GET", "path": "/orders", "model_headers": {
    "Accept": ["application/json", "text/html"], "If-None-Match": ["*"]}}]}
from vibe_audit.worker_entry import Supervisor


@pytest.mark.parametrize("headers,allowed", [
    ({"Accept": "application/json", "Accept-Language": "zh-TW"}, True),
    # Letter case, a repeat under other case and the order of names are all model choices that can encode text.
    ({"accept": "application/json"}, False),
    ({"ACCEPT": "application/json"}, False),
    ({"Accept": "*/*", "aCcEpT": "text/html"}, False),
    ({"Accept-Language": "zh-TW", "Accept": "application/json"}, False),
])
def test_model_header_names_have_one_spelling_and_one_order(headers, allowed):
    assert case_headers_allowed(headers, model_designed=True, vocabulary=LISTED) is allowed
    # Without the operator's list for the endpoint no model header passes at all.
    assert case_headers_allowed(headers, model_designed=True) is False
    # Operator-written cases keep their free spelling and order.
    assert case_headers_allowed(headers) is True


def test_model_header_vocabulary_reads_only_valid_operator_lists():
    from vibe_audit.adapters import model_header_vocabulary
    entry = lambda lists: {"method": "GET", "path": "/a", "model_headers": lists}
    # Two entries for one endpoint add up; method letter case does not matter.
    manifest = {"allowed_requests": [entry({"Accept": ["text/html"]}), entry({"Accept": ["*/*"], "If-None-Match": ["*"]})]}
    assert model_header_vocabulary(manifest, "get", "/a") == {"accept": {"text/html", "*/*"}, "if-none-match": {"*"}}
    assert model_header_vocabulary(manifest, "GET", "/b") == {}
    # A list that RunInput would refuse grants nothing even if it reaches the runtime (defense in depth).
    for bad in ({"accept": ["application/json"]}, {"Accept": ["application/json;q=0.9"]}, {"Accept": "text/html"}, ["Accept"]):
        assert model_header_vocabulary({"allowed_requests": [entry(bad)]}, "GET", "/a") == {}


def test_model_headers_are_canonicalized_and_repeats_refused():
    assert list(canonical_model_headers({"x-requested-with": "XMLHttpRequest", "accept": "*/*"}).items()) == [
        ("Accept", "*/*"), ("X-Requested-With", "XMLHttpRequest")]
    with pytest.raises(ValueError, match="repeats a header name"):
        canonical_model_headers({"Accept": "*/*", "ACCEPT": "text/html"})
    # A name outside the vocabulary keeps its spelling, so the gate still sees and refuses it.
    assert case_headers_allowed(canonical_model_headers({"X-Tenant": "b"}), model_designed=True, vocabulary=LISTED) is False


def test_model_request_sends_defaults_then_its_names_in_sorted_order():
    case = {"method": "GET", "path": "/orders", "designed_by": "model",
            "headers": {"Accept": "text/html", "If-None-Match": "*"}}
    _, _, headers, _, _ = _prepare_request(LISTED_MANIFEST, case)
    assert list(headers.items()) == [("Accept", "text/html"), ("Accept-Encoding", "identity"), ("Connection", "close"),
                                     ("If-None-Match", "*")]
    # The same headers on an endpoint the operator listed nothing for, or on another path, are refused.
    for manifest, request in (({}, case), (LISTED_MANIFEST, {**case, "path": "/orders/1"}),
                              (LISTED_MANIFEST, {**case, "method": "HEAD"})):
        with pytest.raises(AdapterBlocked):
            _prepare_request(manifest, request)
    # A value from the vocabulary that the operator did not list is refused too.
    with pytest.raises(AdapterBlocked):
        _prepare_request(LISTED_MANIFEST, {**case, "headers": {"Accept": "*/*"}})


def test_model_header_choices_that_mean_the_same_look_the_same():
    def sent(headers):
        return list(_prepare_request(LISTED_MANIFEST, {"method": "GET", "path": "/orders", "designed_by": "model", "headers": headers})[2].items())
    # Omitting Accept and sending the default value explicitly are one choice, not two.
    assert sent({}) == sent({"Accept": "application/json"})
    # The charset parameter has one spelling, even when an operator lists the other one.
    assert case_headers_allowed({"Content-Type": "application/json; charset=utf-8"}, model_designed=True, vocabulary=LISTED)
    assert not case_headers_allowed({"Content-Type": "application/json;charset=utf-8"}, model_designed=True, vocabulary=LISTED)


def model_supervisor(monkeypatch, *, model_body=False, designed_by="model", headers=None, model_headers=None):
    monkeypatch.setitem(sys.modules, "adapters", adapters)
    instance = Supervisor.__new__(Supervisor)
    listed = {"Accept": ["application/json"]} if model_headers is None else model_headers
    entry = {"method": "POST", "path": "/chat", **({"model_body": True} if model_body else {}),
             **({"model_headers": listed} if listed else {})}
    instance.manifest = {"allowed_requests": [entry], "auth_profiles": []}
    case = {"id": "C1", "method": "POST", "path": "/chat", "identity": None,
            "headers": headers if headers is not None else {"Accept": "application/json"}, "body": {"q": "hi"}}
    if designed_by:
        case["designed_by"] = designed_by
    instance.spec = {"operation": "tool", "cases": [case]}
    instance.sessions = {}
    return instance


def chat_request(headers=None):
    return {"case_id": "C1", "method": "POST", "path": "/chat", "identity": None,
            "headers": headers or {"Accept": "application/json", "Content-Type": "application/json"},
            "body_b64": base64.b64encode(b'{"q":"hi"}').decode()}


def test_supervisor_sends_a_model_body_only_to_an_operator_marked_endpoint(monkeypatch):
    with pytest.raises(ValueError, match="model_body"):
        model_supervisor(monkeypatch).allowed_request(chat_request())
    case_id, _, method, path, headers, raw, _ = model_supervisor(monkeypatch, model_body=True).allowed_request(chat_request())
    assert (case_id, method, path, raw) == ("C1", "POST", "/chat", b'{"q":"hi"}')
    # The supervisor's own Content-Type joins the model's names in sorted order.
    assert list(headers)[0] == "Accept" and list(headers)[-1] == "Content-Type"
    # An operator-written case is not a model body.
    model_supervisor(monkeypatch, designed_by=None).allowed_request(chat_request())
    # The supervisor's own Content-Type is transport, so the operator lists only what the model wrote.
    assert "Content-Type" not in model_supervisor(monkeypatch, model_body=True).manifest["allowed_requests"][0]["model_headers"]


def test_supervisor_applies_the_header_list_to_model_steps_of_a_sequence_only(monkeypatch):
    monkeypatch.setitem(sys.modules, "adapters", adapters)
    supervisor = Supervisor.__new__(Supervisor)
    supervisor.manifest = {"auth_profiles": [], "allowed_requests": [
        {"method": "GET", "path": "/fixture"}, {"method": "GET", "path": "/private", "model_headers": {"Accept": ["text/html"]}}]}
    step = lambda sid, path, headers: {"id": sid, "case_id": "C1", "method": "GET", "path": path, "identity": None,
                                       "headers": headers, "body": None}
    steps = [step("fixture:setup", "/fixture", {"X-Fixture": "engine"}),   # engine lifecycle step: not a model choice
             step("case", "/private", {"Accept": "text/html"}),            # listed for /private
             step("control:1", "/fixture", {"Accept": "text/html"})]       # /fixture lists nothing
    supervisor.spec = {"operation": "request_sequence", "cases": [{"id": "C1", "designed_by": "model"}], "requests": steps}
    supervisor.sessions, supervisor.sequence_stopped = {}, False
    request = lambda s: {"case_id": "C1", "method": "GET", "path": s["path"], "identity": None, "headers": s["headers"], "body_b64": ""}
    for index, expected in ((0, True), (1, True), (2, False)):
        supervisor.sequence = index
        if expected:
            supervisor.allowed_request(request(steps[index]))
        else:
            with pytest.raises(AdapterBlocked):
                supervisor.allowed_request(request(steps[index]))


def test_supervisor_rechecks_the_operator_header_list_before_tb_target(monkeypatch):
    # A sealed model step with a vocabulary value the operator did not list (as if the case gate had let it through)
    # stops at the last trusted hop; so does any model header on an endpoint with no list.
    for listed in ({"Accept": ["text/html"]}, {}):
        with pytest.raises(AdapterBlocked):
            model_supervisor(monkeypatch, model_body=True, model_headers=listed).allowed_request(chat_request())
    # A model step with no headers of its own needs no list; the Content-Type for its body is the supervisor's.
    model_supervisor(monkeypatch, model_body=True, headers={}, model_headers={}).allowed_request(
        chat_request({"Content-Type": "application/json"}))


def test_supervisor_rechecks_the_model_vocabulary_before_tb_target(monkeypatch):
    # A sealed model step outside the vocabulary (as if the case gate had let it through) stops at the last trusted hop.
    tampered = {"Accept": "application/json", "X-Tenant": "tenant-b"}
    request = chat_request({**tampered, "Content-Type": "application/json"})
    with pytest.raises(AdapterBlocked):
        model_supervisor(monkeypatch, model_body=True, headers=tampered).allowed_request(request)
    # The same headers in an operator-written case are allowed.
    model_supervisor(monkeypatch, designed_by=None, headers=tampered).allowed_request(request)


@pytest.mark.parametrize("environ,shared", [
    # A key bound to a model origin is a model credential even when this run's models do not use it.
    ({"VIBEAUDIT_OPENAI_API_KEY": "k1"}, ["VIBEAUDIT_OPENAI_API_KEY"]),
    ({"VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS": "VIBEAUDIT_LOCAL_KEY=http://127.0.0.1:11434", "VIBEAUDIT_LOCAL_KEY": "k2"},
     ["VIBEAUDIT_LOCAL_KEY"]),
    # The same value under a test identity's own name is still that key.
    ({"VIBEAUDIT_ANTHROPIC_API_KEY": "k3", "VIBEAUDIT_ALICE": "k3"}, ["VIBEAUDIT_ALICE"]),
    # A malformed binding still names the keys it was meant to bind.
    ({"VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS": "VIBEAUDIT_LOCAL_KEY=not-a-url"}, ["VIBEAUDIT_LOCAL_KEY"]),
    ({"VIBEAUDIT_ALICE": "target-only"}, []),
])
def test_bound_model_keys_never_become_target_credentials(environ, shared):
    names = ["VIBEAUDIT_OPENAI_API_KEY", "VIBEAUDIT_LOCAL_KEY", "VIBEAUDIT_ALICE"]
    manifest = {"models": [], "auth_profiles": [{"id": n.lower(), "credential_env": n} for n in names
                                                  if n in environ or n == "VIBEAUDIT_LOCAL_KEY" and "LOCAL" in str(environ)]}
    assert adapters.shared_credentials(manifest, environ) == shared


def test_supervisor_environment_and_requests_refuse_a_bound_model_key(monkeypatch):
    from vibe_audit.worker_runtime import _client_env
    monkeypatch.setenv("VIBEAUDIT_OPENAI_API_KEY", "sk-synthetic-not-a-key")
    manifest = {"models": [], "auth_profiles": [{"id": "alice", "credential_env": "VIBEAUDIT_OPENAI_API_KEY"}]}
    assert "VIBEAUDIT_OPENAI_API_KEY" not in _client_env(manifest)
    with pytest.raises(AdapterBlocked, match="model credential"):
        _prepare_request(manifest, {"method": "GET", "path": "/orders", "identity": "alice"})


def test_supervisor_manifest_names_model_credentials_without_their_values(monkeypatch):
    from vibe_audit.worker_runtime import supervisor_manifest
    monkeypatch.setenv("VIBEAUDIT_LOCAL_MODEL_KEY", "k-model")
    manifest = {"run_id": "r", "models": [{"id": "m", "credential_env": "VIBEAUDIT_LOCAL_MODEL_KEY", "endpoint": "http://127.0.0.1:1"}],
                "auth_profiles": [{"id": "alice", "credential_env": "VIBEAUDIT_LOCAL_MODEL_KEY"}]}
    narrow = supervisor_manifest(manifest)
    assert narrow["models"] == [{"credential_env": "VIBEAUDIT_LOCAL_MODEL_KEY"}]
    # The supervisor's own last check now sees the model key name, as the full manifest would.
    assert adapters.shared_credentials(narrow, {}) == ["VIBEAUDIT_LOCAL_MODEL_KEY"]
    with pytest.raises(AdapterBlocked, match="model credential"):
        _prepare_request(narrow, {"method": "GET", "path": "/orders", "identity": "alice"})


async def test_osv_findings_name_only_records_in_the_provisioned_database(tmp_path, monkeypatch):
    import json, zipfile
    from vibe_audit.worker_runtime import WorkerRuntime
    database = tmp_path / "osv"
    archive = database / "osv-scanner" / "PyPI" / "all.zip"
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("PYSEC-2024-1.json", "{}")
    output = {"results": [{"source": {"path": "/src/requirements.txt"}, "packages": [
        {"vulnerabilities": [{"id": "PYSEC-2024-1"}, {"id": "PYSEC-2024-" + "4142".zfill(12)}]}]}]}
    runtime = WorkerRuntime(tmp_path / "work", backend="process_test", allow_process_test=True, offline_db_dir=str(database))
    try:
        async def execute_tool(spec, **kwargs):
            return {"status": "completed", "stdout": json.dumps(output), "exit_code": 1}
        monkeypatch.setattr(runtime, "execute_tool", execute_tool)
        result = await runtime.run_scanner("osv", str(tmp_path), manifest={}, cancel_event=None)
    finally:
        runtime.leases.close()
    assert sorted(f["rule_id"] for f in result["findings"]) == ["PYSEC-2024-1", "unrecognized-rule"]


def test_staged_line_count_reads_only_the_listed_unchanged_file(tmp_path):
    import os
    from vibe_audit.staging import stage_source, staged_line_count
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("a\nb\n")
    (source / "one.txt").write_text("no newline")
    record = stage_source(str(source), tmp_path / "private")
    assert staged_line_count(record, "app.py") == 3 and staged_line_count(record, "one.txt") == 1
    assert staged_line_count(record, "missing.py") is None and staged_line_count(record, "../repo/app.py") is None
    changed = os.path.join(record["path"], "app.py")
    os.chmod(changed, 0o644)
    with open(changed, "a") as handle:
        handle.write("\n" * 5000)
    # The count is of the copy the scanner saw, so a file that no longer matches its recorded hash counts nothing.
    assert staged_line_count(record, "app.py") is None


def test_live_run_keeps_the_source_path_it_checked(tmp_path, monkeypatch):
    import os
    from fastapi.testclient import TestClient
    from vibe_audit.api import create_app
    from vibe_audit.staging import stage_source
    root = tmp_path / "roots"
    (root / "a" / "b" / "c" / "d").mkdir(parents=True)
    (root / "a" / "repo").mkdir()
    (root / "a" / "repo" / "app.py").write_text("ok = 1\n")
    # roots/link/../../../repo is roots/a/repo while link points four levels down; were link swapped for a plain
    # directory, the same text would name a directory two levels above the root.
    (root / "link").symlink_to(root / "a" / "b" / "c" / "d")
    crafted = os.path.join(str(root), "link", "..", "..", "..", "repo")
    monkeypatch.setenv("VIBEAUDIT_SOURCE_ROOTS", str(root))
    profiles = [{"id": key, "role": "commander" if key == "commander" else "reviewer", "provider": "openai_compatible",
                 "model_id": "m-" + key, "family": "f-" + key, "endpoint": "http://127.0.0.1:9/v1"} for key in ("commander", "a", "b", "c")]
    with TestClient(create_app(tmp_path / "data", testing=True)) as client:
        session = client.get("/api/session", headers={"X-VibeAudit-Token": client.app.state.session_token})
        client.headers["X-CSRF-Token"] = session.json()["csrf_token"]
        created = client.post("/api/runs", json={"mode": "live", "source_path": crafted, "models": profiles,
                                                 "target_url": "http://127.0.0.1:9000", "allowed_target_ips": ["127.0.0.1"],
                                                 "budget": {"max_seconds": 60, "max_requests": 5, "max_model_calls": 10, "max_tokens": 10000}})
        assert created.status_code == 201, created.text
        # The stored path is the one the root check saw, with no link and no "..".
        assert created.json()["manifest"]["source_path"] == str((root / "a" / "repo").resolve())
        # A retest of a finished live run checks and keeps its own source path the same way.
        store = client.app.state.store
        parent = store.get(created.json()["id"])
        parent.update(status="incomplete", findings=[{"id": "F1", "title": "t"}])
        store.save(parent)
        retest = client.post(f"/api/runs/{parent['id']}/retest", json={"name": "Retest", "source_path": crafted,
                                                                      "deployment_id": "v2", "finding_ids": ["F1"]})
        assert retest.status_code == 201, retest.text
        assert retest.json()["manifest"]["source_path"] == str((root / "a" / "repo").resolve())
    # Staging reads a path literally, so it refuses one that still has "..", even through plain directories.
    for path in [crafted, os.path.join(str(root), "a", "b", "..", "repo")]:
        with pytest.raises(ValueError, match="'..'"):
            stage_source(path, tmp_path / "private")
    assert stage_source(str(root / "a" / "repo"), tmp_path / "private")["files"][0]["path"] == "app.py"


def sequence_supervisor(monkeypatch, *, results):
    """A supervisor for one http_case with two positive controls; forward answers from results, in order."""
    import threading
    monkeypatch.setitem(sys.modules, "adapters", adapters)
    instance = Supervisor.__new__(Supervisor)
    controls = [{"name": f"secret control name {n}", "method": "GET", "path": f"/fixture{n}", "identity": None,
                 "expected_status": 200, "required_text": ["CANARY"]} for n in (1, 2)]
    case = {"id": "C1", "title": "model title carrying text", "threat_ids": ["T1"], "adapter": "http", "method": "GET",
            "path": "/private", "identity": None, "headers": {}, "body": None, "designed_by": "model", "repetitions": 3,
            "side_effects": False, "preconditions": ["an unverified string", *controls], "hash": "h",
            "oracle": {"kind": "deny_sensitive", "forbidden_text": ["CANARY"], "allowed_statuses": [403],
                       "required_observations": ["http_response"]}}
    instance.spec = {"operation": "http_case", "cases": [case], "run_id": "r"}
    instance.manifest = {"mode": "live", "target_url": "http://127.0.0.1:9", "allowed_target_ips": ["127.0.0.1"],
                         "allowed_requests": [{"method": "GET", "path": p} for p in ("/fixture1", "/fixture2", "/private")],
                         "auth_profiles": []}
    instance.task = {"broker_token": "t"}
    instance.cap = {"ttl_seconds": 5}
    instance.worker_id = "w"
    instance.revoked = threading.Event()
    instance.dispatch_lock, instance.grant_lock = threading.Lock(), threading.Lock()
    instance.grants, instance.sessions, instance.broker_observations = {}, {}, []
    instance.sequence, instance.sequence_stopped = 0, False
    instance.policy_blocked, instance.unknown_dispatch = None, False
    class Lease:
        def validate(self, *a): pass
        def reserve_dispatch(self, *a): pass
        def finish_dispatch(self, *a): pass
    instance.lease = Lease()
    def emit(value):
        if value.get("kind") == "request":
            pending = instance.grants[value["request_id"]]
            pending[1] = True
            pending[0].set()
    instance.emit = emit
    answers = iter(results)
    instance.forward = lambda method, path, headers, body: {"status_code": 200, "body": next(answers), "peer_ip": "127.0.0.1"}
    return instance


def get(path):
    return {"broker_token": "t", "case_id": "C1", "method": "GET", "path": path, "identity": None, "headers": {}, "body_b64": ""}


def test_http_case_sends_its_controls_then_its_case_once_in_order(monkeypatch):
    supervisor = sequence_supervisor(monkeypatch, results=["CANARY ok", "CANARY ok", "denied"])
    # The case before its controls, a control out of order or twice: none is the worker's choice.
    for path in ["/private", "/fixture2"]:
        with pytest.raises(ValueError, match="next sealed sequence step"):
            supervisor.broker_request(get(path))
    supervisor.broker_request(get("/fixture1"))
    with pytest.raises(ValueError, match="next sealed sequence step"):
        supervisor.broker_request(get("/fixture1"))
    supervisor.broker_request(get("/fixture2"))
    supervisor.broker_request(get("/private"))
    # One pass per task: the controller schedules each repetition as its own task.
    with pytest.raises(ValueError, match="exhausted"):
        supervisor.broker_request(get("/fixture1"))
    assert [row["path"] for row in supervisor.broker_observations] == ["/fixture1", "/fixture2", "/private"]


def test_http_case_stops_at_an_unmet_control(monkeypatch):
    supervisor = sequence_supervisor(monkeypatch, results=["no fixture here"])
    supervisor.broker_request(get("/fixture1"))
    # The target's answer, not the worker, decides that the case is not sent.
    for path in ["/fixture2", "/private"]:
        with pytest.raises(ValueError, match="unmet prerequisite"):
            supervisor.broker_request(get(path))


def test_worker_gets_only_what_it_needs_to_send_and_judge_the_case(monkeypatch):
    supervisor = sequence_supervisor(monkeypatch, results=[])
    view = supervisor.worker_view()
    case = view["cases"][0]
    assert set(case) == {"id", "adapter", "method", "path", "headers", "body", "identity", "designed_by", "side_effects",
                         "repetitions", "oracle", "preconditions"}
    assert [c["name"] for c in case["preconditions"]] == ["control-1", "control-2"]
    assert "model title" not in json.dumps(view) and "secret control name" not in json.dumps(view)
    # The supervisor keeps the sealed spec it checks requests against; other operations pass through unchanged.
    assert supervisor.spec["cases"][0]["title"] == "model title carrying text"
    supervisor.spec = {**supervisor.spec, "operation": "tool"}
    assert supervisor.worker_view() is supervisor.spec


def test_model_oracle_texts_are_bounded_but_operator_ones_are_not():
    from pydantic import ValidationError
    from vibe_audit.contracts import CaseProposal, OperatorCase
    case = {"id": "C1", "title": "t", "threat_ids": ["T1"], "requirement_id": "R1", "adapter": "http", "path": "/x",
            "oracle": {"kind": "deny_sensitive", "forbidden_text": ["x" * 121], "required_observations": ["http_response"]}}
    with pytest.raises(ValidationError):
        CaseProposal.model_validate(case)
    control = {"name": "c", "path": "/f", "expected_status": 200, "required_text": ["y" * 121]}
    with pytest.raises(ValidationError):
        CaseProposal.model_validate({**case, "oracle": {**case["oracle"], "forbidden_text": ["x"]}, "preconditions": [control]})
    OperatorCase.model_validate({**case, "preconditions": [control]})


def test_sequence_worker_gets_steps_without_labels_or_case_text(monkeypatch):
    supervisor = sequence_supervisor(monkeypatch, results=[])
    case = supervisor.spec["cases"][0]
    steps = [{"id": "control:secret control name 1", "case_id": "C1", "method": "GET", "path": "/fixture1", "identity": None,
              "headers": {}, "body": None, "expected_status": 200, "required_text": ["CANARY"], "purpose": "control"},
             {"id": "case", "case_id": "C1", "method": "GET", "path": "/private", "identity": None, "headers": {}, "body": None,
              "expected_status": None, "required_text": [], "capture_session": {"slot": "s", "json_field": "token"}}]
    supervisor.spec = {"operation": "request_sequence", "cases": [case], "requests": steps}
    view = supervisor.worker_view()
    assert [s["id"] for s in view["requests"]] == ["step-1", "step-2"]
    assert all(set(s) <= {"id", "case_id", "method", "path", "headers", "identity", "body", "expected_status", "required_text"} for s in view["requests"])
    assert "secret control name" not in json.dumps(view) and "model title" not in json.dumps(view)
    # The supervisor and console judge a sequence from the supervisor's records, so its worker gets the case ID and
    # each step's request, with no oracle and no expected answer.
    assert view["cases"] == [{"id": "C1"}] and "CANARY" not in json.dumps(view)
    assert not any({"expected_status", "required_text"} & set(step) for step in view["requests"])
    # The supervisor still checks requests against its own sealed steps.
    assert supervisor.spec["requests"][0]["id"].startswith("control:")


def test_worker_task_file_carries_the_worker_view(monkeypatch):
    supervisor = sequence_supervisor(monkeypatch, results=[])
    supervisor.task.update(backend="process_test")
    supervisor.spec["timeout_seconds"] = 30
    task = supervisor.child_task({"tcp": ["127.0.0.1", 1]})
    assert task["spec"] == supervisor.worker_view() and "model title" not in json.dumps(task)
    assert task["broker"] == {"tcp": ["127.0.0.1", 1]} and task["broker_token"] == "t"
    # Without a broker there is no token to hand over either.
    assert supervisor.child_task(None)["broker_token"] is None


@pytest.mark.parametrize("record,completed", [
    ({"status_code": 200, "body": "reset done", "complete": True}, True),
    ({"status_code": 500, "body": "reset done", "complete": True}, False),
    ({"status_code": 200, "body": "nothing", "complete": True}, False),
    # The expected status with an answer the supervisor could not relay, or a request that was never sent: the
    # supervisor stopped there, so the step is unmet whatever the worker reports.
    ({"status_code": 200, "body": "", "complete": False, "denied": "Target response was incomplete"}, False),
    ({"status_code": None, "body": "", "complete": False, "denied": "not sent"}, False),
])
def test_a_sequence_completes_only_when_the_supervisor_saw_every_expected_answer(record, completed):
    from vibe_audit.worker_runtime import supervised_sequence
    steps = [{"id": "reset", "method": "POST", "path": "/reset", "expected_status": 200,
              "required_text": ["reset done"] if record["complete"] else []}]
    claim = {"status": "completed", "observations": [{"status_code": record["status_code"], "body": record["body"]}],
             "broker_observations": [record], "cleanup_confirmed": True}
    # The worker no longer knows a step's expected answer; a failed last cleanup step must not read as completed.
    result = supervised_sequence({"requests": steps}, claim)
    assert (result["status"] == "completed") is completed
    # A login step that should have captured a session is unmet without the supervisor's capture.
    login = [{"id": "login", "method": "POST", "path": "/login", "expected_status": 200, "capture_session": {"slot": "s", "json_field": "token"}}]
    for captured, done in [(True, True), (False, False)]:
        record = {"status_code": 200, "body": "{}", "complete": True, "capture_success": captured}
        claim = {"status": "completed", "observations": [{"status_code": 200, "body": "{}"}], "broker_observations": [record]}
        assert (supervised_sequence({"requests": login}, claim)["status"] == "completed") is done
