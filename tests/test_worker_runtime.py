import asyncio
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
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
    again=await runtime.run_case(scope,case(),cancel_event=asyncio.Event(),request_hook=hook)
    assert again["status"]=="blocked"
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


async def test_deployment_change_revokes_before_later_requests(runtime,target):
    origin,seen=target;scope=manifest(origin)
    scope.update(deployment_header="X-Deployment",deployment_id="v1")
    steps=[{"id":"control","method":"GET","path":"/fixture","expected_status":200,"required_text":["TEST-CANARY"]},
           {"id":"main","method":"GET","path":"/private","expected_status":403},
           {"id":"later","method":"GET","path":"/leak","expected_status":200}]
    result=await runtime.execute_tool({"operation":"request_sequence","cases":[case()],"requests":steps,"timeout_seconds":30},manifest=scope,cancel_event=asyncio.Event(),request_hook=allow)
    assert result["status"]=="blocked",result
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
    assert supervised_verdict(case(),result)==result


def test_sequence_rows_must_match_supervisor_records():
    from vibe_audit.worker_runtime import supervised_sequence
    spec={"requests":[{"id":"control"},{"id":"main"}]}
    records=[recorded("/fixture",200,"TEST-CANARY"),recorded("/private",403,"Forbidden")]
    honest={"status":"completed","observations":[{"id":"control","status_code":200,"body":"TEST-CANARY"},{"id":"main","status_code":403,"body":"Forbidden"}],"broker_observations":records}
    assert supervised_sequence(spec,honest)==honest
    forged=copy.deepcopy(honest);forged["observations"][1]["body"]="Forbidden, honestly"
    assert supervised_sequence(spec,forged)["status"]=="execution_error"
    invented=copy.deepcopy(honest);invented["broker_observations"]=records[:1]
    assert supervised_sequence(spec,invented)["status"]=="execution_error"
    # The relay's 502 for a request the supervisor refused ends the sequence; it is not a forgery.
    refused={"status":"inconclusive","observations":[honest["observations"][0],{"id":"main","status_code":502,"body":"Broker denied request"}],"broker_observations":records[:1]}
    assert supervised_sequence(spec,refused)==refused


def test_controller_redacts_decoded_artifacts_and_escaped_credentials(monkeypatch):
    from vibe_audit.worker_runtime import redact_credentials
    monkeypatch.setenv("VIBEAUDIT_TEST_KEY",'key-"q"-0123456789')
    scope={"auth_profiles":[],"models":[{"id":"m","credential_env":"VIBEAUDIT_TEST_KEY"}]}
    result=redact_credentials({"artifacts":{"zap.json":json.dumps({"evidence":'key-"q"-0123456789'}).encode()},
                               "observations":[{"body":'raw key-"q"-0123456789'}]},scope)
    assert result["artifacts"]["zap.json"]==b'{"evidence": "[REDACTED_CREDENTIAL]"}'
    assert result["observations"][0]["body"]=="raw [REDACTED_CREDENTIAL]"


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
