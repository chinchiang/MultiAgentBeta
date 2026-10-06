import asyncio
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import pytest
from vibe_audit.lease import canonical_hash,LeaseStore
from vibe_audit.worker_runtime import WorkerRuntime,WorkerBlocked,docker_command


def manifest(origin="http://127.0.0.1:1"):
    return {"run_id":uuid.uuid4().hex,"mode":"live","target_url":origin,"allowed_target_ips":["127.0.0.1"],
            "allowed_requests":[{"method":"GET","path":p} for p in ("/fixture","/private","/leak")],"auth_profiles":[],"budget":{"max_requests":10,"max_seconds":30}}


def case(path="/private"):
    value={"id":"case-1","adapter":"http","method":"GET","path":path,"headers":{},"body":None,"identity":None,
           "side_effects":False,"repetitions":1,"preconditions":[{"name":"fixture","method":"GET","path":"/fixture","expected_status":200,"required_text":["TEST-CANARY"]}],
           "oracle":{"kind":"deny_sensitive","forbidden_text":["TEST-CANARY"],"allowed_statuses":[403],"required_observations":["http_response"]},"threat_model_hash":"trusted-threat-hash","source_digest":"snapshot"}
    value["hash"]=canonical_hash(value);return value


@pytest.fixture
def target():
    seen=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            seen.append(self.path)
            body=b"TEST-CANARY" if self.path in {"/fixture","/leak"} else b"Forbidden"
            self.send_response(200 if self.path in {"/fixture","/leak"} else 403)
            self.send_header("X-Deployment","v1" if self.path=="/fixture" else "v2")
            self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    yield f"http://127.0.0.1:{server.server_port}",seen
    server.shutdown();server.server_close();thread.join(timeout=2)


@pytest.fixture
def runtime(tmp_path):
    rt=WorkerRuntime(tmp_path,backend="process_test",allow_process_test=True,ttl_seconds=5)
    yield rt
    rt.leases.close()


async def allow(**kwargs):return None


async def test_each_scheduled_repetition_sends_the_case_once(runtime,target):
    # The engine runs one task per repetition; the worker must not loop over the count again.
    origin,seen=target
    repeated=case();repeated["repetitions"]=3;repeated["hash"]=canonical_hash({k:v for k,v in repeated.items() if k!="hash"})
    for repetition in range(3):
        result=await runtime.run_case(manifest(origin),repeated,cancel_event=asyncio.Event(),request_hook=allow,repetition=repetition)
        assert result["status"]=="pass" and result["requests"]==2,result
    assert seen==["/fixture","/private"]*3


async def test_finished_journal_result_is_reused_not_replayed(runtime,target):
    """A controller crash after the worker finished reuses the paid journaled
    result; the target must not see a replayed request."""
    origin,seen=target
    spec={"operation":"http_case","tool_id":"http_case","cases":[case()],"phase":"blackbox","timeout_seconds":5}
    scope=manifest(origin)
    first=await runtime.execute_tool(dict(spec),manifest=scope,cancel_event=asyncio.Event(),request_hook=allow)
    assert first["status"]=="pass",first
    assert seen==["/fixture","/private"]
    replayed=await runtime.execute_tool(dict(spec),manifest=scope,cancel_event=asyncio.Event(),request_hook=allow)
    assert replayed["status"]=="pass" and replayed.get("resumed_from_journal") is True,replayed
    # The journaled result was enriched before journaling, so the reuse carries
    # the supervisor's isolation, lifecycle and simulated markers.
    assert replayed["isolation"]=="process_unisolated_test_only" and replayed["lifecycle"] and replayed["task_id"] and replayed["simulated"] is True
    # No request reached the target a second time.
    assert seen==["/fixture","/private"]


async def test_sustained_lease_outage_fails_closed_after_three_strikes(tmp_path,monkeypatch):
    """The controller-side three-strike fail-safe must actually fire: three
    consecutive non-LeaseError renewal failures revoke the worker."""
    rt=WorkerRuntime(tmp_path,backend="process_test",allow_process_test=True,ttl_seconds=0.2)
    try:
        real=rt.leases.renew
        # Renewals must keep the capability alive until the supervisor has claimed
        # it: process startup is slower on some platforms, and the sustained
        # outage under test begins once a worker exists, not before it can start.
        def fail_once_claimed(capability,*args,**kwargs):
            with rt.leases.lock:
                row=rt.leases._sql("SELECT state FROM worker_leases WHERE id=?",(capability["id"],)).fetchone()
            if row and row[0]=="active": raise RuntimeError("lease database unavailable")
            return real(capability,*args,**kwargs)
        monkeypatch.setattr(rt.leases,"renew",fail_once_claimed)
        result=await rt.execute_tool({"operation":"selftest","selftest":"spawn_child","timeout_seconds":30},
                                     manifest=manifest(),cancel_event=asyncio.Event(),request_hook=allow)
        assert result["status"]=="outcome_unknown"
        tasks=rt.leases._sql("SELECT state FROM worker_tasks").fetchall()
        assert tasks and {row[0] for row in tasks}=={"outcome_unknown"}
    finally:
        rt.leases.close()


async def test_unfinished_journal_collision_stays_blocked(runtime):
    """A prepared task without a recorded result is never implicitly replayed."""
    c=case()
    spec={"operation":"http_case","tool_id":"http_case","cases":[c],"phase":"blackbox","timeout_seconds":5}
    scope=manifest()
    cap=runtime.leases.issue(run_id=scope["run_id"],case_hash=c["hash"],threat_hash="trusted-threat-hash",
                             manifest_hash=canonical_hash(scope),max_requests=5,ttl_seconds=5,max_seconds=30,
                             operation="http_case",repetition=0,spec_hash=canonical_hash(spec))
    assert runtime.leases.task(cap["task_id"])["state"]=="prepared"
    result=await runtime.execute_tool(dict(spec),manifest=scope,cancel_event=asyncio.Event(),request_hook=allow)
    assert result["status"]=="blocked" and "already exists" in result["reason"],result


async def test_real_independent_process_and_broker_preserve_oracle(runtime,target):
    origin,seen=target;scope=manifest(origin);requests=[]
    async def hook(**ctx):requests.append(ctx)
    result=await runtime.run_case(scope,case(),cancel_event=asyncio.Event(),request_hook=hook)
    assert result["status"]=="pass",result
    assert result["isolation"]=="process_unisolated_test_only"
    assert result["worker_status"]=="pass" and {o["recorded_by"] for o in result["observations"]}=={"supervisor"}
    assert result["cleanup_confirmed"] is True
    assert seen==["/fixture","/private"]
    assert [r["path"] for r in requests]==seen
    assert result["lifecycle"].index("network_revoked")<result["lifecycle"].index("worker_termination_started")
    assert runtime.leases.task(result["task_id"])["state"]=="finished"
    assert result["work_dir_removed"] is True
    assert not list(runtime.root.glob("w-*"))
    # The journal holds this exact task finished: the paid result is reused and
    # no request reaches the target a second time. (run_case rebuilds the verdict
    # from supervisor records, so the reuse marker is visible on execute_tool only.)
    again=await runtime.run_case(scope,case(),cancel_event=asyncio.Event(),request_hook=hook)
    assert again["status"]=="pass"
    assert seen==["/fixture","/private"]
    assert not list(runtime.root.glob("w-*"))


async def test_broker_rejects_unscoped_positive_control_without_target_io(runtime,target):
    origin,seen=target;scope=manifest(origin);scope["allowed_requests"]=[{"method":"GET","path":"/private"}]
    result=await runtime.run_case(scope,case(),cancel_event=asyncio.Event(),request_hook=allow)
    assert result["status"]!="pass"
    assert seen==[]


async def test_controller_denial_prevents_real_dispatch(runtime,target):
    origin,seen=target
    async def deny(**_):raise RuntimeError("Budget denied")
    result=await runtime.run_case(manifest(origin),case(),cancel_event=asyncio.Event(),request_hook=deny)
    assert result["status"]!="pass" and seen==[]


@pytest.fixture
def awkward_target():
    """Answers the broker cannot relay: a redirect, a non-UTF-8 body and a HEAD with Content-Length."""
    seen=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def answer(self,status,body,head=False,**headers):
            seen.append((self.command,self.path))
            self.send_response(status)
            for name,value in headers.items():self.send_header(name,value)
            self.send_header("Content-Length",str(len(body)));self.end_headers()
            if not head:self.wfile.write(body)
        def do_GET(self):
            if self.path=="/fixture":self.answer(200,b"TEST-CANARY")
            elif self.path=="/redirect":self.answer(302,b"",Location="/login")
            elif self.path=="/latin":self.answer(403,b"\xe9chec")
            else:self.answer(403,b"Forbidden")
        def do_HEAD(self):self.answer(200,b"TEST-CANARY",head=True)
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length","0")))
            self.answer(302,b"",Location="/done")
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    yield f"http://127.0.0.1:{server.server_port}",seen
    server.shutdown();server.server_close();thread.join(timeout=2)


def scoped(origin,*requests):
    scope=manifest(origin);scope["allowed_requests"]=[{"method":m,"path":p} for m,p in [("GET","/fixture"),*requests]]
    return scope


def sealed_case(**fields):
    value=case();value.update(fields);value["hash"]=canonical_hash({k:v for k,v in value.items() if k!="hash"})
    return value


@pytest.mark.parametrize("path",["/redirect","/latin"])
async def test_unrelayable_answer_to_a_read_only_case_is_known_not_unknown(runtime,awkward_target,path):
    # A 302 to a login page is a common denial: it must end this case, not the whole live run.
    origin,seen=awkward_target
    result=await runtime.run_case(scoped(origin,("GET",path)),sealed_case(path=path),cancel_event=asyncio.Event(),request_hook=allow)
    assert result["status"] in {"inconclusive","blocked"} and result["cleanup_confirmed"] is True,result
    assert seen==[("GET","/fixture"),("GET",path)]
    denied=[row for row in result["broker_observations"] if row["path"]==path]
    assert denied and denied[0]["complete"] is False and denied[0]["denied"]
    assert runtime.leases.task(result["task_id"])["state"]=="finished"


async def test_head_answer_has_no_body_whatever_its_content_length(runtime,awkward_target):
    origin,seen=awkward_target
    steps=[{"id":"head","method":"HEAD","path":"/fixture","expected_status":200}]
    scope=scoped(origin,("HEAD","/fixture"))
    head_case=sealed_case(method="HEAD",path="/fixture",preconditions=[])
    result=await runtime.execute_tool({"operation":"request_sequence","cases":[head_case],"requests":steps,"timeout_seconds":30},manifest=scope,cancel_event=asyncio.Event(),request_hook=allow)
    assert result["status"]=="completed",result
    assert [(row["status_code"],row["body"]) for row in result["observations"]]==[(200,"")]


async def test_refused_connection_sends_nothing_and_ends_only_the_case(runtime):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1",0));port=probe.getsockname()[1]
    result=await runtime.run_case(manifest(f"http://127.0.0.1:{port}"),case(),cancel_event=asyncio.Event(),request_hook=allow)
    assert result["status"]=="inconclusive" and result["cleanup_confirmed"] is True,result
    assert result["broker_observations"][0]["denied"].startswith("Target connection failed")


async def test_unsafe_request_answered_by_redirect_stays_outcome_unknown(runtime,awkward_target):
    origin,seen=awkward_target
    steps=[{"id":"change","method":"POST","path":"/orders","body":{},"expected_status":200}]
    post_case=sealed_case(method="POST",path="/orders",body={},preconditions=[],side_effects=True)
    result=await runtime.execute_tool({"operation":"request_sequence","cases":[post_case],"requests":steps,"timeout_seconds":30},manifest=scoped(origin,("POST","/orders")),cancel_event=asyncio.Event(),request_hook=allow)
    assert result["status"]=="outcome_unknown",result
    assert seen==[("POST","/orders")]


async def test_unmet_sequence_prerequisite_ends_the_sequence_with_a_known_answer(runtime,target):
    origin,seen=target
    steps=[{"id":"control","method":"GET","path":"/private","expected_status":200},
           {"id":"main","method":"GET","path":"/leak","expected_status":403}]
    result=await runtime.execute_tool({"operation":"request_sequence","cases":[case()],"requests":steps,"timeout_seconds":30},manifest=manifest(origin),cancel_event=asyncio.Event(),request_hook=allow)
    assert result["status"]=="inconclusive" and result["cleanup_confirmed"] is True,result
    assert seen==["/private"]
    assert [(row["id"],row["status_code"]) for row in result["observations"]]==[("control",403)]


async def test_deployment_change_revokes_before_later_requests(runtime,target):
    origin,seen=target;scope=manifest(origin)
    scope.update(deployment_header="X-Deployment",deployment_id="v1")
    steps=[{"id":"control","method":"GET","path":"/fixture","expected_status":200,"required_text":["TEST-CANARY"]},
           {"id":"main","method":"GET","path":"/private","expected_status":403},
           {"id":"later","method":"GET","path":"/leak","expected_status":200}]
    result=await runtime.execute_tool({"operation":"request_sequence","cases":[case()],"requests":steps,"timeout_seconds":30},manifest=scope,cancel_event=asyncio.Event(),request_hook=allow)
    assert result["status"]=="blocked" and result["deployment_changed"] is True,result
    assert seen==["/fixture","/private"]


async def test_broker_and_controller_redact_every_configured_credential(runtime,monkeypatch):
    alice,bob,model="alice-"+"a"*20,"bob-"+"b"*20,'model-"quoted"-'+"m"*12
    for key,value in [("VIBEAUDIT_TEST_ALICE",alice),("VIBEAUDIT_TEST_BOB",bob),("VIBEAUDIT_TEST_MODEL",model)]:
        monkeypatch.setenv(key,value)
    reflected=json.dumps({"bob":bob,"model":model}).encode()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            body=b"TEST-CANARY" if self.path=="/fixture" else reflected
            self.send_response(200 if self.path=="/fixture" else 403)
            self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        scope=manifest(f"http://127.0.0.1:{server.server_port}")
        monkeypatch.setenv("VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS",",".join(f"{k}={scope['target_url']}" for k in ("VIBEAUDIT_TEST_ALICE","VIBEAUDIT_TEST_BOB")))
        scope["auth_profiles"]=[{"id":"alice","credential_env":"VIBEAUDIT_TEST_ALICE"},{"id":"bob","credential_env":"VIBEAUDIT_TEST_BOB"}]
        scope["models"]=[{"id":"reviewer-a","credential_env":"VIBEAUDIT_TEST_MODEL"}]
        value=case();value.pop("hash");value["identity"]="alice";value["hash"]=canonical_hash(value)
        result=await runtime.run_case(scope,value,cancel_event=asyncio.Event(),request_hook=allow)
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)
    assert result["status"]=="pass",result
    dump=json.dumps(result)
    assert not [s for s in (alice,bob,model,json.dumps(model)[1:-1]) if s in dump]
    # The broker hashed what it handed to the sandboxed tool: Bob's token was already gone, the model key
    # (which the supervisor never holds) is removed by the controller.
    row=next(r for r in result["broker_observations"] if r["path"]=="/private")
    brokered=reflected.decode().replace(bob,"[REDACTED_CREDENTIAL]")
    assert row["body_sha256"]==hashlib.sha256(brokered.encode()).hexdigest()


def recorded(path,status,body,identity=None):
    return {"case_id":"case-1","method":"GET","path":path,"identity":identity,"status_code":status,"body":body,"complete":True}


@pytest.mark.parametrize("claim,main,expected",[
    ("pass",recorded("/private",200,"TEST-CANARY"),"fail"),         # a leak the supervisor saw cannot be hidden
    ("fail",recorded("/private",403,"Forbidden"),"inconclusive"),   # nor can a finding be invented
    ("pass",recorded("/private",403,"Forbidden"),"pass"),
    ("pass",recorded("/private",403,"Forbidden",identity="tenant-b"),"inconclusive"),
])
def test_controller_verdict_comes_from_supervisor_records(claim,main,expected):
    from vibe_audit.worker_runtime import supervised_verdict
    result=supervised_verdict(case(),{"status":claim,"reason":"worker says so","observations":[{"kind":"http_response","provenance":"adapter.http","case_id":"case-1"}],
                                      "broker_observations":[recorded("/fixture",200,"TEST-CANARY"),main]})
    assert (result["status"],result["worker_status"])==(expected,claim)
    assert all(o["recorded_by"]=="supervisor" for o in result["observations"])


def test_controller_keeps_worker_failure_states():
    from vibe_audit.worker_runtime import supervised_verdict
    result={"status":"outcome_unknown","reason":"lost","broker_observations":[recorded("/private",200,"TEST-CANARY")]}
    kept=supervised_verdict(case(),result)
    assert (kept["status"],kept["reason"],kept["broker_observations"])==("outcome_unknown","lost",result["broker_observations"])


@pytest.mark.parametrize("claim",["blocked","execution_error","completed","outcome_unknown"])
def test_supervisor_recorded_leak_stands_whatever_the_worker_returns(claim):
    from vibe_audit.worker_runtime import supervised_verdict
    # Extra keys are the worker's claims: none may replace the supervisor's verdict.
    result=supervised_verdict(case(),{"status":claim,"security_status":"pass","fixture_observations":[{"kind":"precondition"}],
                                      "broker_observations":[recorded("/fixture",200,"TEST-CANARY"),recorded("/private",200,"TEST-CANARY")]})
    assert result["status"]=="fail" and result["worker_status"]==claim
    assert "security_status" not in result and "fixture_observations" not in result
    # A leak recorded before a dispatch was lost is still a finding, but the target needs a reset first.
    assert result.get("target_state_confirmed",True) is (claim!="outcome_unknown")


def test_sequence_rows_must_match_supervisor_records():
    from vibe_audit.worker_runtime import supervised_sequence
    spec={"requests":[{"id":"control"},{"id":"main"}]}
    records=[recorded("/fixture",200,"TEST-CANARY"),recorded("/private",403,"Forbidden")]
    honest={"status":"completed","observations":[{"id":"control","status_code":200,"body":"TEST-CANARY"},{"id":"main","status_code":403,"body":"Forbidden"}],"broker_observations":records}
    rows=lambda result:[(row["id"],row["status_code"],row["body"]) for row in result["observations"]]
    checked=supervised_sequence(spec,honest)
    assert checked["status"]=="completed" and rows(checked)==[("control",200,"TEST-CANARY"),("main",403,"Forbidden")]
    forged=copy.deepcopy(honest);forged["observations"][1]["body"]="Forbidden, honestly"
    assert supervised_sequence(spec,forged)["status"]=="execution_error"
    invented=copy.deepcopy(honest);invented["broker_observations"]=records[:1]
    assert supervised_sequence(spec,invented)["status"]=="execution_error"
    # Step labels and fixture observations come from the sealed order, never from the worker.
    relabelled=copy.deepcopy(honest);relabelled["observations"][0]["id"]="main";relabelled["observations"][1]["id"]="control:fixture"
    relabelled["fixture_observations"]=[{"kind":"precondition","name":"fixture","value":True}]
    checked=supervised_sequence(spec,relabelled)
    assert rows(checked)==[("control",200,"TEST-CANARY"),("main",403,"Forbidden")] and "fixture_observations" not in checked
    # The relay's 502 for a request the supervisor refused ends the sequence; it is not a forgery.
    refused={"status":"inconclusive","observations":[honest["observations"][0],{"id":"main","status_code":502,"body":"Broker denied request"}],"broker_observations":records[:1]}
    checked=supervised_sequence(spec,refused)
    assert checked["status"]=="inconclusive" and rows(checked)==[("control",200,"TEST-CANARY")]


def test_controller_redacts_decoded_artifacts_and_escaped_credentials(monkeypatch):
    from vibe_audit.worker_runtime import redact_credentials
    monkeypatch.setenv("VIBEAUDIT_TEST_KEY",'key-"q"-0123456789')
    scope={"auth_profiles":[],"models":[{"id":"m","credential_env":"VIBEAUDIT_TEST_KEY"}]}
    result=redact_credentials({"artifacts":{"zap.json":json.dumps({"evidence":'key-"q"-0123456789'}).encode()},
                               "observations":[{"body":'raw key-"q"-0123456789'}]},scope)
    assert result["artifacts"]["zap.json"]==b'{"evidence": "[REDACTED_CREDENTIAL]"}'
    assert result["observations"][0]["body"]=="raw [REDACTED_CREDENTIAL]"


def test_supervisor_never_receives_a_model_key_as_a_target_credential(monkeypatch):
    from vibe_audit.worker_runtime import _client_env
    monkeypatch.setenv("VIBEAUDIT_ALICE_TOKEN","alice-token")
    monkeypatch.setenv("VIBEAUDIT_BOB_TOKEN","shared-model-key")
    monkeypatch.setenv("VIBEAUDIT_MODEL_KEY","shared-model-key")
    monkeypatch.setenv("VIBEAUDIT_CAROL_TOKEN","carol-token")
    monkeypatch.setenv("VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS","VIBEAUDIT_ALICE_TOKEN=http://127.0.0.1:9000,VIBEAUDIT_BOB_TOKEN=http://127.0.0.1:9000,"
                       "VIBEAUDIT_CAROL_TOKEN=http://127.0.0.1:9001")
    scope={"target_url":"http://127.0.0.1:9000",
           "auth_profiles":[{"id":p,"credential_env":f"VIBEAUDIT_{p.upper()}_TOKEN"} for p in ("alice","bob","carol")],
           "models":[{"id":"m","credential_env":"VIBEAUDIT_MODEL_KEY"}]}
    env=_client_env(scope)
    assert env["VIBEAUDIT_ALICE_TOKEN"]=="alice-token"
    assert "VIBEAUDIT_BOB_TOKEN" not in env and "VIBEAUDIT_MODEL_KEY" not in env
    # A credential bound to another origin never enters the supervisor's environment; the binding itself does,
    # so the supervisor's own last check reads the operator's environment, not the run.
    assert "VIBEAUDIT_CAROL_TOKEN" not in env and env["VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS"].startswith("VIBEAUDIT_ALICE_TOKEN=")
    monkeypatch.setenv("VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS","not a binding")
    assert not {"VIBEAUDIT_ALICE_TOKEN","VIBEAUDIT_CAROL_TOKEN"}&set(_client_env(scope))


def test_supervisor_that_cannot_start_reports_nothing_to_clean_up(tmp_path):
    from vibe_audit.worker_entry import read_frame
    entry=Path(__file__).resolve().parents[1]/"backend"/"vibe_audit"/"worker_entry.py"
    # The capability names a different specification, so the supervisor refuses before any worker exists.
    task={"capability":{"id":"lease","token":"t","binding":{"spec_hash":"another-spec"}},"worker_id":"w","spec":{"tool_id":"http_case"},
          "database_path":str(tmp_path/"leases.sqlite3"),"manifest":{}}
    done=subprocess.run([sys.executable,"-I",str(entry),"supervise"],input=(json.dumps(task)+"\n").encode(),capture_output=True,timeout=30)
    assert done.returncode==2
    import io
    result=read_frame(io.BytesIO(done.stdout))["result"]
    assert (result["status"],result["cleanup_confirmed"],result["not_started"])==("blocked",True,True)


async def test_supervisor_pipe_failure_cleans_up_instead_of_leaking(runtime,monkeypatch):
    """A supervisor that dies before reading its task must not leave the lease,
    the active table or the outcome unsettled: control or observation failure cannot count as clean."""
    class ClosedPipe:
        def write(self,data):raise BrokenPipeError("supervisor died before reading its task")
        async def drain(self):pass
        def is_closing(self):return False
        def close(self):pass
    class DeadSupervisor:
        class Stream:
            def __init__(self):self.data=b""
            async def readline(self):return self.data
            async def read(self,size=-1):return self.data
        def __init__(self):
            self.pid=424242;self.returncode=None;self.stdin=ClosedPipe()
            self.stdout=self.Stream();self.stderr=self.Stream()
        async def wait(self):self.returncode=1;return 1
    spawned=[]
    async def broken_exec(*args,**kwargs):
        spawned.append(args);return DeadSupervisor()
    monkeypatch.setattr(asyncio,"create_subprocess_exec",broken_exec)
    result=await runtime.execute_tool({"operation":"http_case","tool_id":"http_case","cases":[case()],"phase":"blackbox","timeout_seconds":5},
                                      manifest=manifest(),cancel_event=asyncio.Event(),request_hook=allow)
    assert spawned
    assert (result["status"],result["cleanup_confirmed"])==("outcome_unknown",False)
    assert runtime.active=={}
    states=[row[0] for row in runtime.leases._sql("SELECT state FROM worker_tasks").fetchall()]
    assert states and set(states)<={"outcome_unknown"}


async def test_tool_inventory_resolves_pins_like_execution(tmp_path):
    """The inventory must describe the pin execution would actually use."""
    shared="example/worker@sha256:"+"a"*64
    rt=WorkerRuntime(tmp_path,backend="docker",image_pins={"worker":shared},allow_process_test=True)
    try:
        rows=await rt.tool_inventory()
        by_id={row["id"]:row for row in rows}
        assert all(row["image_pin"]==shared for row in rows)
        assert by_id["semgrep"]["image_pin"]==by_id["zap"]["image_pin"]==shared
    finally:
        rt.leases.close()


async def test_pre_send_revocation_is_known_not_unknown(runtime,monkeypatch):
    """Nothing that never reached the target may demand reconciliation: an egress
    revocation or lease expiry before the request is sent stays a known outcome."""
    import sys
    import vibe_audit.adapters as adapters_module
    from vibe_audit import lease as lease_module
    from vibe_audit.worker_entry import NotSent,Supervisor
    monkeypatch.setitem(sys.modules,"adapters",adapters_module)
    # The worker runs these modules flat in production; map them so the same class objects are compared here.
    monkeypatch.setitem(sys.modules,"lease",lease_module)
    sup=Supervisor.__new__(Supervisor)
    sup.manifest=manifest()
    sup.lease=runtime.leases
    sup.worker_id="w"
    sup.socket_lock=threading.Lock()
    sup.sockets=set()
    sup.revoked=threading.Event()
    sup.cap=runtime.leases.issue(run_id="pre-send",case_hash="case",threat_hash="threat",manifest_hash="m",
                                 max_requests=5,ttl_seconds=5,max_seconds=30,operation="http_case",repetition=0,spec_hash="s")
    runtime.leases.claim(sup.cap,"w")
    sup.revoked.set()
    with pytest.raises(NotSent):
        sup.forward("GET","/private",{},None)
    assert not getattr(sup,"unknown_dispatch",False)
    # An expired lease also stops the request before it is sent.
    expired=runtime.leases.issue(run_id="pre-send-2",case_hash="case",threat_hash="threat",manifest_hash="m",
                                 max_requests=5,ttl_seconds=0.1,max_seconds=30,operation="http_case",repetition=1,spec_hash="s")
    runtime.leases.claim(expired,"w")
    sup.cap=expired;sup.revoked=threading.Event()
    await asyncio.sleep(0.15)
    with pytest.raises(NotSent):
        sup.forward("GET","/private",{},None)


def test_controller_redacts_credentials_reflected_in_escaped_forms(monkeypatch):
    from vibe_audit.worker_runtime import redact_credentials
    monkeypatch.setenv("VIBEAUDIT_TEST_KEY","bob/secret token")
    scope={"auth_profiles":[{"id":"bob","credential_env":"VIBEAUDIT_TEST_KEY"}],"models":[]}
    for reflected in ['bob\\/secret token','bob%2Fsecret%20token','bob/secret token']:
        assert "[REDACTED_CREDENTIAL]" in redact_credentials({"body":"echo "+reflected},scope)["body"]


def test_broker_reads_no_oversized_frame_before_its_token_check():
    import io
    from vibe_audit.worker_entry import read_frame,BROKER_FRAME
    with pytest.raises(ValueError,match="oversized"):
        read_frame(io.BytesIO(b"{" + b" "*(BROKER_FRAME+10) + b"}\n"),BROKER_FRAME)
    assert read_frame(io.BytesIO(b'{"ok":true}\n'),BROKER_FRAME)=={"ok":True}


@pytest.mark.skipif(os.name!="posix",reason="Hard-crash integration uses POSIX process semantics")
def test_controller_hard_crash_leaves_independent_guardian_to_revoke_and_kill(tmp_path):
    import vibe_audit.worker_runtime as module
    backend=str(Path(module.__file__).parents[1]);root=tmp_path/"runtime";marker=tmp_path/"ready.json"
    script=tmp_path/"controller.py"
    script.write_text("import sys,asyncio,json\nfrom pathlib import Path\nsys.path.insert(0,"+repr(backend)+")\nfrom vibe_audit.worker_runtime import WorkerRuntime\n"
        +"async def go():\n rt=WorkerRuntime("+repr(str(root))+",backend='process_test',allow_process_test=True,ttl_seconds=5)\n"
        +" async def allow(**kw):pass\n"
        +" op=asyncio.create_task(rt.execute_tool({'operation':'selftest','selftest':'spawn_child','timeout_seconds':60},manifest="+repr(manifest())+",cancel_event=asyncio.Event(),request_hook=allow))\n"
        +" for i in range(500):\n  values=list(rt.active.values())\n  if values and (Path(values[0]['work_dir'])/'out/child_pid.txt').exists():\n   Path("+repr(str(marker))+ ").write_text(json.dumps(values[0]))\n   break\n  await asyncio.sleep(.05)\n await op\nasyncio.run(go())\n")
    controller=subprocess.Popen([sys.executable,"-I",str(script)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        deadline=time.monotonic()+30
        while not marker.exists() and time.monotonic()<deadline:time.sleep(.05)
        assert marker.exists()
        active=json.loads(marker.read_text());controller.kill();controller.wait(timeout=5)
        result_file=Path(active["work_dir"])/"supervisor-result.json"
        deadline=time.monotonic()+20
        while not result_file.exists() and time.monotonic()<deadline:time.sleep(.05)
        result=json.loads(result_file.read_text())
        assert result["status"]=="outcome_unknown" and result["cleanup_confirmed"]
        assert result["lifecycle"].index("network_revoked")<result["lifecycle"].index("worker_termination_started")
        store=LeaseStore(root/"worker-leases.sqlite3")
        try:assert store.task(active["capability"]["task_id"])["state"]=="outcome_unknown"
        finally:store.close()
    finally:
        if controller.poll() is None:controller.kill();controller.wait(timeout=5)


async def test_cancel_closes_network_before_killing_process_tree(runtime):
    cancel=asyncio.Event()
    operation=asyncio.create_task(runtime.execute_tool({"operation":"selftest","selftest":"spawn_child","timeout_seconds":30},manifest=manifest(),cancel_event=cancel,request_hook=allow))
    for _ in range(500):
        active=list(runtime.active.values())
        if active and (Path(active[0]["work_dir"])/"out/child_pid.txt").exists():break
        await asyncio.sleep(.05)
    assert active
    child_pid=int((Path(active[0]["work_dir"])/"out/child_pid.txt").read_text())
    cancel.set();result=await asyncio.wait_for(operation,30)
    assert result["status"]=="outcome_unknown"
    assert result["lifecycle"].index("network_revoked")<result["lifecycle"].index("worker_termination_started")
    if os.name=="posix":
        try:
            os.kill(child_pid,0)
            status=Path(f"/proc/{child_pid}/stat").read_text().split()[2]
            assert status=="Z"  # reparented, already dead, pending init reaping
        except ProcessLookupError:pass


def test_guardian_tolerates_transient_lease_errors(runtime,monkeypatch):
    """One lease-database hiccup must not kill a mid-flight worker; three
    consecutive failures still fail closed."""
    import sys
    import time as time_module
    from vibe_audit import lease as lease_module
    from vibe_audit.worker_entry import Supervisor
    monkeypatch.setitem(sys.modules,"lease",lease_module)
    class FlakyLease:
        def __init__(self):self.calls=0
        def validate(self,cap,worker_id):
            self.calls+=1
            raise RuntimeError("database is locked")
        def revoke(self,*args,**kwargs):pass
    sup=Supervisor.__new__(Supervisor)
    sup.cap=runtime.leases.issue(run_id="guardian",case_hash="c",threat_hash="t",manifest_hash="m",
                                 max_requests=5,ttl_seconds=5,max_seconds=30,operation="http_case",repetition=0,spec_hash="s")
    sup.worker_id="w"
    sup.lease=FlakyLease()
    sup.revoked=threading.Event()
    sup.controller_alive=True
    sup.last_heartbeat=time_module.monotonic()
    sup.sockets=set();sup.socket_lock=threading.Lock()
    sup.grants={};sup.grant_lock=threading.Lock()
    revoked=[]
    monkeypatch.setattr(sup,"revoke_network",lambda reason="":(revoked.append(reason),sup.revoked.set()))
    thread=threading.Thread(target=sup.guardian,daemon=True);thread.start()
    deadline=time_module.monotonic()+0.4
    while sup.lease.calls<2 and time_module.monotonic()<deadline:time_module.sleep(0.02)
    assert not revoked and sup.lease.calls>=1
    thread.join(timeout=3)
    assert revoked==["Durable lease authority unavailable"]


async def test_heartbeat_renews_off_the_event_loop(tmp_path,monkeypatch):
    """A slow lease database must not stall the controller event loop: renewal
    runs in a worker thread while grants and results keep flowing."""
    # A generous TTL keeps the supervisor's guardian from failing closed on
    # platform scheduling jitter alone: three missed heartbeats must stay far
    # above normal process-spawn and thread-wakeup latency.
    rt=WorkerRuntime(tmp_path,backend="process_test",allow_process_test=True,ttl_seconds=2.0)
    try:
        loop_thread=threading.get_ident()
        real=rt.leases.renew
        idents=[]
        def wrapped(capability,*args,**kwargs):
            idents.append(threading.get_ident())
            return real(capability,*args,**kwargs)
        monkeypatch.setattr(rt.leases,"renew",wrapped)
        cancel=asyncio.Event()
        operation=asyncio.create_task(rt.execute_tool({"operation":"selftest","selftest":"spawn_child","timeout_seconds":30},manifest=manifest(),cancel_event=cancel,request_hook=allow))
        # Heartbeats renew every ttl/3, so this window guarantees >=3 renewals.
        await asyncio.sleep(2.2)
        cancel.set()
        result=await asyncio.wait_for(operation,30)
        assert result["status"]=="outcome_unknown"
        assert len(idents)>=3,idents
        assert loop_thread not in set(idents)
    finally:
        rt.leases.close()


def test_docker_control_confirms_absent_container_and_reports_real_failures(monkeypatch):
    """The production teardown path: a daemon-reported missing container counts as
    confirmed cleanup, while daemon failures stay unconfirmed."""
    import vibe_audit.worker_entry as worker_entry_module
    from vibe_audit.worker_entry import Supervisor
    sup=Supervisor.__new__(Supervisor)
    sup.task={"container_name":"vibeaudit-worker-"+"a"*32}
    def absent(method,path,timeout=5):return (404,b"no such container")
    monkeypatch.setattr(worker_entry_module,"docker_api",absent)
    assert sup.docker_control("kill",sup.task["container_name"]) is True
    assert sup.docker_control("wait",sup.task["container_name"]) is True
    assert sup.docker_control("rm","--force",sup.task["container_name"]) is True
    def failing(method,path,timeout=5):return (500,b"daemon unavailable")
    monkeypatch.setattr(worker_entry_module,"docker_api",failing)
    assert sup.docker_control("wait",sup.task["container_name"]) is False
    def raising(method,path,timeout=5):raise OSError("socket gone")
    monkeypatch.setattr(worker_entry_module,"docker_api",raising)
    assert sup.docker_control("kill",sup.task["container_name"]) is False
    assert sup.docker_control("invent",sup.task["container_name"]) is False


@pytest.mark.parametrize("options,available",[
    (["name=apparmor","name=seccomp,profile=builtin","name=cgroupns"],True),
    (["name=seccomp,profile=default","name=userns"],True),
    (["name=apparmor","name=seccomp,profile=unconfined"],False),
    (["name=apparmor"],False),
    (None,False),
])
async def test_docker_runtime_requires_a_seccomp_profile(tmp_path,monkeypatch,options,available):
    import vibe_audit.worker_entry as worker_entry_module
    class Leases:
        postgres=True
    def info(method,path,timeout=5):
        return 200,{"OSType":"linux",**({"SecurityOptions":options} if options is not None else {})}
    monkeypatch.setattr(worker_entry_module,"docker_api",info)
    rt=WorkerRuntime(tmp_path,lease_store=Leases(),docker_binary="/usr/bin/docker")
    result=await rt.capabilities()
    assert result["available"] is available
    if available:
        assert result["production_ready"] is True and "seccomp" in result["security_options"]
    else:
        assert "seccomp" in result["reason"] and "production_ready" not in result


def test_docker_namespace_identity_mounts_are_fixed(tmp_path):
    dirs=[]
    for name in ("inputs","out","broker"):
        path=tmp_path/name;path.mkdir();dirs.append(path)
    kwargs=dict(prefix=["docker","--host","unix:///var/run/docker.sock"],image="sha256:"+"a"*64,name="vibeaudit-worker-"+"b"*32,inputs=dirs[0],broker=dirs[2])
    black=docker_command(**kwargs,phase="blackbox")
    white=docker_command(**kwargs,phase="whitebox")
    assert black[black.index("--network")+1]=="none"
    assert black[black.index("--user")+1]=="65533:65533"
    assert white[white.index("--user")+1]=="65532:65532"
    assert not any("target=/src" in arg for arg in black)
    assert not any("docker.sock,target" in arg for arg in black)
    # Tool output lives in a bounded in-container tmpfs, never a world-writable host directory.
    assert not any("target=/out" in arg for arg in black)
    assert black[black.index("/out:rw,nosuid,nodev,noexec,size=64m,mode=1777")-1]=="--tmpfs"
    # A white-box scanner parsing a hostile repository has no broker socket to reach the supervisor through.
    assert any("target=/broker" in arg for arg in black) and not any("target=/broker" in arg for arg in white)
    with pytest.raises(WorkerBlocked):docker_command(**kwargs,phase="blackbox",source_dir=tmp_path)


@pytest.mark.skipif(not (os.getenv("VIBEAUDIT_TEST_DATABASE_URL") and os.getenv("VIBEAUDIT_TEST_WORKER_IMAGE")),reason="Real Linux Docker image/PostgreSQL not provisioned")
async def test_real_docker_nonroot_network_none_without_source(tmp_path):
    store=LeaseStore(database_url=os.environ["VIBEAUDIT_TEST_DATABASE_URL"])
    rt=WorkerRuntime(tmp_path,lease_store=store,image_pins={"worker":os.environ["VIBEAUDIT_TEST_WORKER_IMAGE"]},ttl_seconds=5)
    try:
        result=await rt.execute_tool({"operation":"selftest","timeout_seconds":30},manifest=manifest(),cancel_event=asyncio.Event(),request_hook=allow)
        assert result["status"]=="completed",result
        assert result["isolation"]=="docker_network_none"
        inspected=json.loads(result["stdout"])
        assert inspected["uid"]==65533 and inspected["source_visible"] is False
        assert inspected["interfaces"]==["lo"]
        assert result["cleanup_confirmed"]
    finally:store.close()


async def test_white_box_task_gets_no_broker_target_scope_or_credentials(runtime,monkeypatch):
    from vibe_audit.worker_runtime import _client_env,phase_scope,supervisor_manifest
    monkeypatch.setenv("VIBEAUDIT_ALICE_TOKEN","alice-token")
    scope=manifest()
    scope["auth_profiles"]=[{"id":"alice","credential_env":"VIBEAUDIT_ALICE_TOKEN"}]
    monkeypatch.setenv("VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS","VIBEAUDIT_ALICE_TOKEN="+scope["target_url"])
    white=phase_scope(scope,"whitebox")
    assert not {"target_url","allowed_target_ips","allowed_requests","auth_profiles"}&set(supervisor_manifest(white))
    assert "VIBEAUDIT_ALICE_TOKEN" not in _client_env(white) and _client_env(phase_scope(scope,"blackbox"))["VIBEAUDIT_ALICE_TOKEN"]=="alice-token"
    offered={}
    for phase in ("whitebox","blackbox"):
        # A fresh run for each phase: the same run and operation would reuse the first task's journaled result.
        result=await runtime.execute_tool({"operation":"selftest","phase":phase,"timeout_seconds":30},manifest={**scope,"run_id":uuid.uuid4().hex},
                                          cancel_event=asyncio.Event(),request_hook=allow)
        assert result["status"]=="completed",result
        offered[phase]=json.loads(result["stdout"])["broker_offered"]
    assert offered=={"whitebox":False,"blackbox":True}


async def test_white_box_supervisor_is_started_without_target_credentials(runtime,monkeypatch):
    monkeypatch.setenv("VIBEAUDIT_ALICE_TOKEN","alice-token")
    scope=manifest()
    scope["auth_profiles"]=[{"id":"alice","credential_env":"VIBEAUDIT_ALICE_TOKEN"}]
    monkeypatch.setenv("VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS","VIBEAUDIT_ALICE_TOKEN="+scope["target_url"])
    started={}
    async def refuse(*args,env=None,**kwargs):
        started[len(started)]=env
        raise OSError("synthetic: supervisor not started")
    monkeypatch.setattr(asyncio,"create_subprocess_exec",refuse)
    for phase in ("whitebox","blackbox"):
        await runtime.execute_tool({"operation":"selftest","phase":phase,"timeout_seconds":30},manifest={**scope,"run_id":uuid.uuid4().hex},
                                   cancel_event=asyncio.Event(),request_hook=allow)
    assert "VIBEAUDIT_ALICE_TOKEN" not in started[0] and started[1]["VIBEAUDIT_ALICE_TOKEN"]=="alice-token"


async def test_real_worker_sees_only_its_view_of_a_model_case(runtime,target):
    origin,seen=target
    value=case();value.pop("hash")
    value.update(title="model-written title text",designed_by="model")
    value["preconditions"][0]["name"]="model-written control name"
    value["hash"]=canonical_hash(value)
    result=await runtime.run_case(manifest(origin),value,cancel_event=asyncio.Event(),request_hook=allow)
    assert result["status"]=="pass",result
    # The worker reports what it was given: a numbered control, and nothing the model wrote only to pass on.
    assert [o.get("name") for o in result["worker_observations"] if o.get("kind")=="precondition"]==["control-1"]
    assert "model-written" not in json.dumps(result["worker_observations"])
    # The supervisor's own records keep the sealed case's names.
    assert [o["name"] for o in result["observations"] if o["kind"]=="precondition"]==["model-written control name"]
