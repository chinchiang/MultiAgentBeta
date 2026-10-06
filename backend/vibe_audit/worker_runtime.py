"""Independent worker runtime with durable, expiring egress capabilities.

Production requires a local Linux Docker daemon and PostgreSQL leases. The
explicit process_test backend exercises supervision only and is never an OS
security boundary. Neither backend implicitly retries an external task.
"""
from __future__ import annotations
import asyncio
import base64
import copy
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import re
import secrets
import shutil
import sys
import tempfile
import uuid

from .lease import LeaseStore,LeaseError,canonical_hash
from .staging import remove_private_tree

HERE=Path(__file__).resolve().parent
IMAGE=re.compile(r"(?:[A-Za-z0-9._:/-]+@)?sha256:[a-f0-9]{64}\Z")
TOOLS={"semgrep":"semgrep","gitleaks":"gitleaks","osv":"osv-scanner","zap":"zap.sh","schemathesis":"st","playwright":"node","promptfoo":"promptfoo","pyrit":"python3"}


class WorkerBlocked(RuntimeError):
    pass


def load_config(profile_id="default",config_path=None):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}",profile_id): raise WorkerBlocked("Invalid runtime profile ID")
    path=config_path or os.getenv("VIBEAUDIT_RUNTIME_CONFIG")
    if not path: raise WorkerBlocked("Trusted runtime configuration is not provisioned")
    data=json.loads(Path(path).read_text(encoding="utf-8"))
    profile=(data.get("profiles",data)).get(profile_id)
    if not isinstance(profile,dict): raise WorkerBlocked("Runtime profile is not provisioned")
    allowed={"work_root","database_url","database_url_env","backend","image_pins","ttl_seconds","allow_process_test","docker_binary","offline_db_dir"}
    if set(profile)-allowed: raise WorkerBlocked("Unsupported trusted runtime setting")
    result=copy.deepcopy(profile)
    if key:=result.pop("database_url_env",None):
        if not re.fullmatch(r"VIBEAUDIT_[A-Z0-9_]+",key): raise WorkerBlocked("Invalid lease database credential reference")
        result["database_url"]=os.environ.get(key)
        if not result["database_url"]: raise WorkerBlocked("Lease database credential is unavailable")
    return result


def _safe_relative(value):
    path=PurePosixPath(value)
    if not isinstance(value,str) or not value or "\\" in value or path.is_absolute() or any(p in {".",".."} for p in path.parts) or ":" in value or any(ord(c)<32 for c in value):
        raise WorkerBlocked("Worker file paths must be safe relative paths")
    return path


# Matches worker_entry.MAX_FRAME: one supervisor result line may carry every bounded response twice.
SUPERVISOR_FRAME=64*1024*1024


def supervisor_manifest(manifest):
    """The supervisor's part of the run: scope, identities, budget and, by name only, the model credentials.

    The names let adapters.shared_credentials refuse a test identity that is a model key at the last trusted
    hop before the target; the values never reach the supervisor's environment (see _client_env)."""
    narrow={k:manifest[k] for k in ("run_id","mode","target_url","allowed_target_ips","allowed_requests","auth_profiles","budget","deployment_id","deployment_header") if k in manifest}
    narrow["models"]=[{"credential_env":p["credential_env"]} for p in manifest.get("models",[]) if isinstance(p,dict) and p.get("credential_env")]
    return narrow


def phase_scope(manifest,phase):
    """A white-box task's supervisor sends nothing to a target, so it gets no target scope, identities or credentials."""
    return manifest if phase=="blackbox" else {k:v for k,v in manifest.items() if k not in {"target_url","allowed_target_ips","allowed_requests","auth_profiles"}}


def _client_env(manifest):
    from .adapters import AdapterBlocked,TARGET_CREDENTIAL_ORIGINS_ENV,credential_env_allowed,shared_credentials,unbound_target_credentials
    from .worker_entry import clean_env
    result=clean_env()
    # A model key must never reach the supervisor that talks to the target, even under a second name;
    # nor may a test credential the environment has not bound to this run's target.
    shared=set(shared_credentials(manifest))
    try:
        unbound=set(unbound_target_credentials(manifest))
    except AdapterBlocked:
        unbound={p.get("credential_env","") for p in manifest.get("auth_profiles",[])}
    for profile in manifest.get("auth_profiles",[]):
        key=profile.get("credential_env","")
        if credential_env_allowed(key) and key in os.environ and key not in shared and key not in unbound:
            result[key]=os.environ[key]
    # The binding names target origins, so only a supervisor that sends as an identity gets it.
    if manifest.get("auth_profiles") and TARGET_CREDENTIAL_ORIGINS_ENV in os.environ:
        result[TARGET_CREDENTIAL_ORIGINS_ENV]=os.environ[TARGET_CREDENTIAL_ORIGINS_ENV]
    return result


def redact_credentials(value,manifest):
    """Remove every configured target and model credential, raw or JSON-escaped, from a worker result."""
    found=set()
    for profile in [*manifest.get("auth_profiles",[]),*manifest.get("models",[])]:
        key=profile.get("credential_env","")
        if isinstance(key,str) and re.fullmatch(r"VIBEAUDIT_[A-Z0-9_]+",key) and os.environ.get(key):
            from .adapters import secret_forms
            found.update(secret_forms(os.environ[key]))
    # Longest first, so a credential that contains another is not left half visible.
    values=sorted(found,key=len,reverse=True)
    def redact(item):
        if isinstance(item,str):
            for secret in values: item=item.replace(secret,"[REDACTED_CREDENTIAL]")
        elif isinstance(item,bytes):
            for secret in values: item=item.replace(secret.encode(),b"[REDACTED_CREDENTIAL]")
        elif isinstance(item,list): return [redact(v) for v in item]
        elif isinstance(item,dict): return {k:redact(v) for k,v in item.items()}
        return item
    return redact(value) if values else value


# Set by the supervisor or controller. Any other key in a worker result is only the worker's claim,
# so a worker cannot add a security_status, fixture observations or a step label of its own.
SUPERVISED_FIELDS=("broker_observations","cleanup_confirmed","deployment_changed","isolation","lifecycle","task_id","simulated","work_dir_removed","resumed_from_journal")


def _supervised(result):
    return {key:result[key] for key in SUPERVISED_FIELDS if key in result}


def supervised_verdict(case,result):
    """Re-evaluate an HTTP case from the supervisor's records; the worker's own verdict is only a claim."""
    from .adapters import evaluate_oracle
    def same(step,row):
        return (step.get("method","GET"),step.get("path"),step.get("identity"))==(row.get("method"),row.get("path"),row.get("identity"))
    controls=[p for p in case.get("preconditions",[]) if isinstance(p,dict)]
    observations=[]
    for row in result.get("broker_observations",[]):
        common={"provenance":"adapter.http","case_id":case["id"],"status_code":row.get("status_code"),"recorded_by":"supervisor"}
        if row.get("case_id")!=case["id"]:
            continue
        # The supervisor binds a request to the case before its preconditions, so this order matches its own.
        if same(case,row):
            observations.append({**common,"kind":"http_response","body":row.get("body",""),"complete":row.get("complete") is True,"peer_ip":row.get("peer_ip")})
        elif control:=next((p for p in controls if same(p,row)),None):
            matched=(row.get("complete") is True and row.get("status_code")==control.get("expected_status")
                     and isinstance(row.get("body"),str) and all(text in row["body"] for text in control.get("required_text",[])))
            observations.append({**common,"kind":"precondition","name":control.get("name"),"value":matched,
                                 "matched_text_sha256":[hashlib.sha256(text.encode()).hexdigest() for text in control.get("required_text",[])] if matched else []})
    verdict=evaluate_oracle(case,observations)
    worker=result.get("status")
    if verdict["status"]=="fail":
        # A leak the supervisor recorded stands on its own, whatever the worker or the task's end state claims.
        status,reason=verdict["status"],verdict["reason"]
    elif worker not in {"pass","fail","inconclusive"}:
        # An unfinished task, or a worker without a verdict, can only make the result less conclusive.
        status=worker if worker in {"blocked","execution_error","outcome_unknown"} else "execution_error"
        reason=result.get("reason") or "The worker returned no verdict"
    else:
        # A pass needs both sides to agree.
        status=verdict["status"] if verdict["status"]==worker else "inconclusive"
        reason=verdict["reason"] if status==verdict["status"] else "The worker's verdict and the supervisor's records disagree; no pass is reported."
    supervised={**_supervised(result),"status":status,"reason":reason,"observations":observations,"evidence":[],
                "requests":sum(1 for row in result.get("broker_observations",[]) if row.get("case_id")==case["id"]),
                "worker_status":worker,"worker_reason":result.get("reason"),"worker_observations":result.get("observations",[])}
    if status=="fail" and worker=="outcome_unknown":
        # The violation is a finding, but a later dispatch's effect is unknown: no replay, reset first.
        supervised["target_state_confirmed"]=False
    return supervised


def supervised_sequence(spec,result):
    """Each response a sequence worker reports must be the one the supervisor recorded for that step."""
    rows,records=result.get("observations",[]),result.get("broker_observations",[])
    supervised=_supervised(result)
    mismatch={**supervised,"status":"execution_error","reason":"Worker-reported responses differ from the supervisor's records","observations":[]}
    for index,row in enumerate(rows):
        if index<len(records) and (row.get("status_code"),row.get("body"))==(records[index].get("status_code"),records[index].get("body")):
            continue
        # The relay answers a request the supervisor refused with 502, which ends the sequence unfinished.
        if index==len(rows)-1 and row.get("status_code")==502 and result.get("status")!="completed":
            continue
        return mismatch
    steps=spec.get("requests",[])
    if result.get("status")=="completed" and not len(rows)==len(records)==len(steps):
        return mismatch
    # The supervisor enforced the sealed step order, so record i answers step i whatever the worker labels it.
    observations=[{"id":step.get("id"),"status_code":record.get("status_code"),"body":record.get("body"),"complete":record.get("complete") is True,
                   "capture_success":record.get("capture_success") is True} for step,record in zip(steps,records)]
    status=result.get("status") if result.get("status") in {"completed","inconclusive","blocked","execution_error","outcome_unknown"} else "execution_error"
    reason=result.get("reason")
    # A completed sequence is the supervisor's finding, not the worker's: every sealed step's expected answer must be in
    # its records (the same test the supervisor applies before the next step), so a worker cannot pass a failed reset.
    if status=="completed" and any(_step_unmet(step,record) for step,record in zip(steps,records)):
        status,reason="inconclusive","A sealed step's expected answer is not in the supervisor's records"
    return {**supervised,"status":status,"reason":reason,"observations":observations,"requests":len(records)}


def _step_unmet(step,record):
    body=record.get("body") if isinstance(record.get("body"),str) else ""
    return ((step.get("expected_status") is not None and record.get("status_code")!=step["expected_status"])
            or any(text not in body for text in step.get("required_text",[]))
            or bool(step.get("capture_session")) and record.get("capture_success") is not True)


def docker_command(*,prefix,image,name,phase,inputs,broker,runtime=HERE,source_dir=None,offline_db_dir=None):
    if not IMAGE.fullmatch(image) or not re.fullmatch(r"vibeaudit-worker-[a-f0-9]{32}",name):
        raise WorkerBlocked("An immutable image digest and generated worker name are required")
    if phase not in {"whitebox","blackbox"} or (phase=="blackbox" and source_dir):
        raise WorkerBlocked("Black-box workers cannot receive source mounts")
    uid="65532:65532" if phase=="whitebox" else "65533:65533"
    argv=[*prefix,"run","--name",name,"--pull","never","--network","none","--user",uid,
          "--cap-drop","ALL","--security-opt","no-new-privileges","--read-only","--pids-limit","128",
          "--memory","1g","--memory-swap","1g","--cpus","1","--ulimit","nofile=256:256","--log-driver","none",
          "--tmpfs","/tmp:rw,nosuid,nodev,size=256m,mode=1777","--workdir","/tmp",
          # Only the worker reads /out back, so a bounded tmpfs replaces a world-writable host directory.
          "--tmpfs","/out:rw,nosuid,nodev,noexec,size=64m,mode=1777",
          "--env","HOME=/tmp","--env","PYTHONDONTWRITEBYTECODE=1","--env","PROMPTFOO_DISABLE_TELEMETRY=1"]
    # Only a black-box worker relays requests; a white-box scanner parsing a hostile repository has no broker socket.
    for path,target,readonly in [(inputs,"/inputs",True),*([(broker,"/broker",True)] if phase=="blackbox" else []),(runtime,"/runtime",True)]:
        source=str(Path(path).resolve(strict=True))
        if any(c in source for c in ",\r\n\0"): raise WorkerBlocked("Unsupported bind mount path")
        argv += ["--mount",f"type=bind,source={source},target={target},bind-propagation=rprivate"+(",readonly,bind-recursive=readonly" if readonly else "")]
    if source_dir:
        from .sandbox import _safe_path,_check_source
        source=_safe_path(source_dir);_check_source(source)
        argv += ["--mount",f"type=bind,source={source},target=/src,readonly,bind-propagation=rprivate,bind-recursive=readonly"]
    if offline_db_dir:
        if phase!="whitebox": raise WorkerBlocked("Offline databases are white-box inputs only")
        from .sandbox import _safe_path,_check_source
        db=_safe_path(offline_db_dir);_check_source(db,max_bytes=2*1024*1024*1024)
        if not (db/"osv-scanner").is_dir(): raise WorkerBlocked("OSV database layout is invalid")
        argv += ["--mount",f"type=bind,source={db},target=/opt/osv-db,readonly,bind-propagation=rprivate,bind-recursive=readonly"]
    return [*argv,"--entrypoint","python3",image,"-I","/runtime/worker_entry.py","worker","/inputs/_worker_task.json"]


class WorkerRuntime:
    def __init__(self,work_root,*,database_url=None,lease_store=None,backend="docker",image_pins=None,ttl_seconds=5,allow_process_test=False,docker_binary=None,offline_db_dir=None):
        if isinstance(work_root,dict):
            config=work_root
            work_root=config["work_root"];database_url=config.get("database_url",database_url)
            backend=config.get("backend",backend);image_pins=config.get("image_pins",image_pins)
            ttl_seconds=config.get("ttl_seconds",ttl_seconds);allow_process_test=config.get("allow_process_test",allow_process_test);docker_binary=config.get("docker_binary",docker_binary)
            offline_db_dir=config.get("offline_db_dir",offline_db_dir)
        if backend not in {"docker","process_test"} or (backend=="process_test" and not allow_process_test):
            raise WorkerBlocked("Process supervision requires an explicit test-only opt-in")
        self.root=Path(work_root).resolve();self.root.mkdir(parents=True,exist_ok=True)
        self.leases=lease_store or LeaseStore(self.root/"worker-leases.sqlite3",database_url=database_url)
        self.backend=backend;self.images=image_pins or {};self.ttl=float(ttl_seconds)
        self.docker=docker_binary or shutil.which("docker")
        self.offline_db_dir=offline_db_dir
        self.active={}

    async def capabilities(self):
        if self.backend=="process_test":
            return {"available":True,"isolation":"process_unisolated_test_only","production_ready":False}
        if os.name!="posix" or not self.docker:
            return {"available":False,"reason":"Production workers require the local Linux Docker runtime"}
        if not self.leases.postgres:
            return {"available":False,"reason":"Production worker leases require PostgreSQL"}
        try:
            from .worker_entry import docker_api
            status,info=await asyncio.to_thread(docker_api,"GET","/info")
            if status!=200 or info.get("OSType")!="linux": raise WorkerBlocked("Docker daemon unavailable")
            # Whitebox workers parse hostile repositories; a daemon started without seccomp leaves every syscall open.
            options=[str(item).split(",") for item in info.get("SecurityOptions") or []]
            seccomp=next((item for item in options if item[0]=="name=seccomp"),None)
            if not seccomp or "profile=unconfined" in seccomp:
                return {"available":False,"reason":"The Docker daemon applies no seccomp profile; workers need its default profile"}
            # Recorded with the run, so whether AppArmor, user namespaces or rootless mode also applied stays visible.
            return {"available":True,"isolation":"docker_network_none","production_ready":True,
                    "security_options":sorted(item[0].removeprefix("name=") for item in options)}
        except Exception:
            return {"available":False,"reason":"Local Linux Docker daemon could not be verified"}

    async def tool_inventory(self):
        from .worker_entry import docker_api
        from urllib.parse import quote
        caps=await self.capabilities()
        rows=[]
        for tool in TOOLS:
            # Resolve exactly like execute_tool does, so the inventory never calls a
            # tool unprovisioned when execution would use the shared worker pin.
            pin=self.images.get(tool) or self.images.get("worker")
            installed=False
            if caps.get("available") and self.backend=="docker" and isinstance(pin,str) and IMAGE.fullmatch(pin):
                try:
                    status,details=await asyncio.to_thread(docker_api,"GET","/images/"+quote(pin,safe="")+"/json")
                    installed=status==200 and bool(details.get("Id"))
                except Exception:
                    pass
            rows.append({"id":tool,"available":installed,"implemented":True,"image_pin":pin,
                         "status":"provisioned" if installed else "blocked_provisioning_required",
                         "detail":"固定版本隔離工具已備妥；每次執行仍需通過案例、範圍、預算與證據檢查。" if installed else "工具 adapter 已實作；需要本地 Linux、PostgreSQL 及已下載的固定映像。"})
        return rows

    def _normalize(self,spec,manifest):
        spec=copy.deepcopy(spec)
        phase=spec.get("phase","blackbox")
        if phase not in {"whitebox","blackbox"}: raise WorkerBlocked("Invalid worker phase")
        if phase=="blackbox" and spec.get("source_dir"): raise WorkerBlocked("Black-box source mounts are forbidden")
        operation=spec.get("operation","tool")
        if spec.get("task_stage","execution") not in {"execution","setup","cleanup"}:
            raise WorkerBlocked("Invalid lifecycle task stage")
        if spec.get("task_stage") in {"setup","cleanup"} and operation!="request_sequence":
            raise WorkerBlocked("Cleanup tasks require the sealed sequence protocol")
        if operation not in {"tool","http_case","request_sequence","selftest"}: raise WorkerBlocked("Unknown worker operation")
        if self.backend=="process_test" and operation=="tool": raise WorkerBlocked("Host execution of scanner tools is forbidden; process backend is supervision-test only")
        tool=spec.get("tool_id",operation)
        argv=spec.get("argv",[])
        if operation=="tool" and (tool not in TOOLS or not isinstance(argv,list) or not argv or argv[0]!=TOOLS[tool] or any(not isinstance(a,str) or "\0" in a for a in argv)):
            raise WorkerBlocked("Tool executable does not match its fixed adapter")
        timeout=spec.get("timeout_seconds",120)
        limit=spec.get("max_output_bytes",256*1024)
        if type(timeout) not in {int,float} or not self.ttl<=timeout<=600 or type(limit) is not int or not 1024<=limit<=1024*1024:
            raise WorkerBlocked("Invalid bounded worker resource limits")
        files=spec.pop("input_files",{})
        if not isinstance(files,dict) or len(files)>100: raise WorkerBlocked("Worker input file limit exceeded")
        raw_files={};total=0
        for name,value in files.items():
            _safe_relative(name)
            if name=="_worker_task.json": raise WorkerBlocked("Reserved worker input name")
            value=value.encode() if isinstance(value,str) else value
            if not isinstance(value,bytes): raise WorkerBlocked("Worker input must be bytes or text")
            total+=len(value)
            if total>2*1024*1024: raise WorkerBlocked("Worker input byte limit exceeded")
            raw_files[name]=value
        for name in spec.get("output_files",[]): _safe_relative(name)
        cases=spec.get("cases",[])
        if phase=="blackbox" and operation!="selftest":
            if not cases or len(cases)>100: raise WorkerBlocked("Bound sealed cases are required")
            for case in cases:
                if case.get("hash")!=canonical_hash({k:v for k,v in case.items() if k!="hash"}) or not case.get("threat_model_hash"):
                    raise WorkerBlocked("Case hash or threat binding is invalid")
            if len({c["threat_model_hash"] for c in cases})!=1: raise WorkerBlocked("Cases have different threat model bindings")
        spec.update(operation=operation,tool_id=tool,phase=phase,timeout_seconds=timeout,max_output_bytes=limit,
                    input_digests={name:hashlib.sha256(raw).hexdigest() for name,raw in raw_files.items()},run_id=manifest.get("run_id"))
        spec.pop("manifest",None)
        return spec,raw_files

    async def execute_tool(self,spec,*,manifest=None,cancel_event,request_hook,lease_hook=None,repetition=0):
        manifest=manifest or spec.get("manifest")
        if not isinstance(manifest,dict) or not manifest.get("run_id"):
            return {"status":"blocked","reason":"A bound run manifest is required","cleanup_confirmed":True}
        if request_hook is None:
            return {"status":"blocked","reason":"Controller request authorization hook is required","cleanup_confirmed":True}
        capability=await self.capabilities()
        if not capability.get("available"):
            return {"status":"blocked","reason":capability["reason"],"cleanup_confirmed":True}
        private=proc=cap=None
        try:
            spec,files=self._normalize(spec,manifest)
            if cancel_event is not None and cancel_event.is_set(): raise WorkerBlocked("Run was cancelled")
            if lease_hook: await lease_hook()
            image=spec.get("image_pin") or self.images.get(spec["tool_id"]) or self.images.get("worker")
            if self.backend=="docker" and (not isinstance(image,str) or not IMAGE.fullmatch(image)):
                raise WorkerBlocked("Provision a trusted immutable worker image digest")
            cases=spec.get("cases",[])
            case_hash=cases[0]["hash"] if len(cases)==1 else canonical_hash({"cases":cases,"source_digest":manifest.get("source_digest")})
            threat_hash=cases[0]["threat_model_hash"] if cases else spec.get("threat_model_hash","offline-whitebox")
            binding_args=dict(run_id=manifest["run_id"],case_hash=case_hash,threat_hash=threat_hash,
                              manifest_hash=canonical_hash(manifest),
                              operation=spec["tool_id"]+(":"+spec["task_stage"] if spec.get("task_stage") in {"setup","cleanup"} else ""),
                              repetition=repetition,spec_hash=canonical_hash(spec))
            try:
                cap=await asyncio.to_thread(self.leases.issue,max_requests=min(spec.get("max_requests",100),manifest.get("budget",{}).get("max_requests",100)),
                                      ttl_seconds=self.ttl,max_seconds=spec["timeout_seconds"],**binding_args)
            except LeaseError:
                # A controller crash after the worker finished must not turn paid,
                # journaled work into an unreplayable collision; unfinished tasks
                # keep their reconciliation path.
                resumed=await asyncio.to_thread(self.leases.finished_result,**binding_args)
                if resumed is None:
                    raise
                resumed["resumed_from_journal"]=True
                if isinstance(resumed.get("artifacts"),dict):
                    resumed["artifacts"]={k:base64.b64decode(v) for k,v in resumed["artifacts"].items()}
                if spec.get("operation")=="request_sequence":
                    resumed=supervised_sequence(spec,resumed)
                return redact_credentials(resumed,manifest)
            private=Path(tempfile.mkdtemp(prefix="w-",dir=self.root));os.chmod(private,0o700)
            inputs=private/"inputs";out=private/"out";broker=private/"broker"
            for directory,mode in [(inputs,0o755),(out,0o700),(broker,0o711)]: directory.mkdir();os.chmod(directory,mode)
            for name,data in files.items():
                path=inputs/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);os.chmod(path,0o444)
            worker_id=uuid.uuid4().hex;name="vibeaudit-worker-"+worker_id
            prefix=[self.docker,"--host","unix:///var/run/docker.sock"] if self.backend=="docker" else []
            argv=docker_command(prefix=prefix,image=image,name=name,phase=spec["phase"],inputs=inputs,broker=broker,source_dir=spec.get("source_dir"),offline_db_dir=spec.get("offline_db_dir")) if self.backend=="docker" else [sys.executable,"-I",str(HERE/"worker_entry.py"),"worker",str(inputs/"_worker_task.json")]
            # Only the supervisor receives target credential references; the
            # worker task file contains cases/specification and relay access.
            scope=phase_scope(manifest,spec["phase"])
            narrow=supervisor_manifest(scope)
            child_cap={k:v for k,v in cap.items() if k!="renewal_token"}
            initial={"backend":self.backend,"spec":spec,"manifest":narrow,"capability":child_cap,"worker_id":worker_id,
                     "database_path":self.leases.database_path,"database_url":self.leases.database_url,"broker_token":secrets.token_urlsafe(32),
                     "inputs_dir":str(inputs),"broker_dir":str(broker),"result_file":str(private/"supervisor-result.json"),
                     "argv":argv,"docker_prefix":prefix,"container_name":name}
            options={"creationflags":0x08000200} if os.name=="nt" else {"start_new_session":True}
            proc=await asyncio.create_subprocess_exec(sys.executable,"-I",str(HERE/"worker_entry.py"),"supervise",stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,
                                                       env=_client_env(scope),limit=SUPERVISOR_FRAME+1,**options)
            self.active[cap["task_id"]]={"pid":proc.pid,"capability":cap,"work_dir":str(private)}
            async def send(value):
                proc.stdin.write((json.dumps(value,separators=(",",":"))+"\n").encode());await proc.stdin.drain()
            stop=asyncio.Event()
            beat=errors=None
            result=None
            try:
                # From here on the supervisor exists and the work directory holds unredacted
                # input: any failure must run the teardown below, or the process and its
                # container, socket and files outlive this call.
                await send(initial)
                async def heartbeat():
                    transient=0
                    while not stop.is_set():
                        try:
                            if cancel_event is not None and cancel_event.is_set(): raise WorkerBlocked("Cancelled")
                            if lease_hook: await lease_hook()
                            try:
                                # Renewal is a durable database round trip: run it off the
                                # event loop so a slow lease database cannot stall grant
                                # replies or result reads for every other task.
                                await asyncio.to_thread(self.leases.renew,cap)
                            except LeaseError:
                                raise
                            except Exception:
                                # One transient lease-database error must not kill a healthy
                                # worker; three consecutive failures mean authority is gone.
                                transient+=1
                                if transient>=3: raise
                                # Skip this tick's heartbeat so the counter can actually
                                # accumulate; a short send gap stays inside the lease TTL.
                            else:
                                transient=0
                                await send({"kind":"heartbeat"})
                        except Exception:
                            await asyncio.to_thread(self.leases.revoke,cap["id"],"Controller revoked worker lease")
                            try: await send({"kind":"cancel"})
                            except Exception: pass
                            return
                        try: await asyncio.wait_for(stop.wait(),max(.05,self.ttl/3))
                        except TimeoutError: pass
                async def drain_stderr():
                    total=0
                    while data:=await proc.stderr.read(8192):
                        total+=len(data)
                        if total>256*1024:
                            await asyncio.to_thread(self.leases.revoke,cap["id"],"Supervisor stderr limit exceeded")
                            return
                beat=asyncio.create_task(heartbeat())
                errors=asyncio.create_task(drain_stderr())
                # The supervisor may spend the same bounded create budget the worker's
                # hard deadline allows, then up to 20s confirming teardown: a shorter
                # controller deadline would abandon a healthy worker and invent an
                # unknown outcome for a task it never let finish.
                deadline=asyncio.get_running_loop().time()+spec["timeout_seconds"]+min(45,spec["timeout_seconds"])+25
                while True:
                    raw=await asyncio.wait_for(proc.stdout.readline(),max(.1,deadline-asyncio.get_running_loop().time()))
                    if not raw: break
                    message=json.loads(raw)
                    if message.get("kind")=="request":
                        allow=False
                        try:
                            if cancel_event is not None and cancel_event.is_set(): raise WorkerBlocked("Cancelled")
                            await request_hook(method=message["method"],path=message["path"],case_id=message.get("case_id"),identity=message.get("identity"),purpose=message.get("purpose"))
                            allow=True
                        except Exception: pass
                        await send({"kind":"grant","request_id":message["request_id"],"allow":allow})
                    elif message.get("kind")=="result": result=message["result"];break
            except (Exception,asyncio.CancelledError):
                await asyncio.to_thread(self.leases.revoke,cap["id"],"Controller stopped awaiting worker")
                try: await send({"kind":"cancel"})
                except Exception: pass
            finally:
                stop.set()
                if beat: await beat
                if proc.stdin and not proc.stdin.is_closing(): proc.stdin.close()
                try: await asyncio.wait_for(asyncio.shield(proc.wait()),25)
                except TimeoutError: pass  # Independent guardian remains responsible for teardown.
                if errors: errors.cancel();await asyncio.gather(errors,return_exceptions=True)
                self.active.pop(cap["task_id"],None)
            if result is None:
                await asyncio.to_thread(self.leases.revoke,cap["id"],"No verified supervisor result")
                result={"status":"outcome_unknown","reason":"No complete worker result; do not replay","cleanup_confirmed":False,"task_id":cap["task_id"]}
            if proc.returncode is None:
                # The supervisor delivered its result but outlived the grace period
                # (its own teardown may wait up to ~30s on a stalled daemon):
                # nothing of value remains and a lingering broker socket or task
                # file must not stay on disk. When cleanup was never confirmed the
                # outcome is already unknown and demands reconciliation, so an
                # untracked container stays the operator's documented case.
                proc.kill()
                try: await asyncio.wait_for(proc.wait(),5)
                except TimeoutError: pass
            if result.get("cleanup_confirmed") is True and proc.returncode is not None:
                # The worker is gone; its inputs, outputs and unredacted supervisor record must not stay on disk.
                result["work_dir_removed"]=remove_private_tree(private)
            # Decode first: a credential inside a base64 tool artifact is invisible to text redaction.
            if isinstance(result.get("artifacts"),dict):
                result["artifacts"]={k:base64.b64decode(v) for k,v in result["artifacts"].items()}
            if spec.get("operation")=="request_sequence":
                result=supervised_sequence(spec,result)
            return redact_credentials(result,manifest)
        except Exception as exc:
            # Refused before any supervisor started, so nothing else can still be using
            # the work directory; an issued capability nobody started would otherwise
            # poison this binding forever, so the controller revokes it here.
            if private and proc is None: remove_private_tree(private)
            if cap is not None and proc is None and (await asyncio.to_thread(self.leases.task,cap["task_id"]))["state"] in {"prepared","issued"}:
                await asyncio.to_thread(self.leases.revoke,cap["id"],"Controller could not start the worker")
            # Our own gate messages are fixed local text; an OSError or unexpected
            # error string can embed host paths or database details, so only its
            # type name reaches the run record.
            reason=str(exc) if isinstance(exc,(WorkerBlocked,LeaseError)) else f"{type(exc).__name__}: worker prerequisites failed before any dispatch"
            return {"status":"blocked","reason":reason,"cleanup_confirmed":True}

    async def run_case(self,manifest,case,*,cancel_event,request_hook,lease_hook=None,repetition=0):
        return supervised_verdict(case,await self.execute_tool({"operation":"http_case","tool_id":"http_case","cases":[case],"phase":"blackbox", "timeout_seconds":min(120,manifest.get("budget",{}).get("max_seconds",120))},manifest=manifest,cancel_event=cancel_event,request_hook=request_hook,lease_hook=lease_hook,repetition=repetition))

    async def run_scanner(self,scanner_id,source_dir,*,manifest,cancel_event,request_hook=None,lease_hook=None,image_pin=None,offline_db_dir=None):
        from .sandbox import _parse,osv_database_ids
        offline_db_dir=offline_db_dir or self.offline_db_dir
        async def deny_network(**kwargs):
            raise WorkerBlocked("White-box scanners cannot use target egress")
        request_hook=deny_network
        if scanner_id=="osv" and not offline_db_dir:
            return {"status":"blocked","reason":"A pinned offline OSV database snapshot is required","cleanup_confirmed":True}
        root=HERE.parents[1]
        if scanner_id=="semgrep":
            argv=["semgrep","scan","--config","/inputs/rules.yml","--metrics","off","--disable-version-check","--disable-nosem","--no-git-ignore","--no-autofix","--json","--jobs","1","--timeout","5","/src"]
            files={"rules.yml":(root/"fixtures/semgrep-rules.yml").read_bytes()}
        elif scanner_id=="gitleaks":
            argv=["gitleaks","dir","/src","--config","/inputs/gitleaks.toml","--gitleaks-ignore-path","/dev/null","--redact","--report-format","json","--report-path","/dev/stdout","--no-banner"]
            files={"gitleaks.toml":(root/"fixtures/gitleaks.toml").read_bytes()}
        elif scanner_id=="osv":
            argv=["osv-scanner","scan","source","--offline","--recursive","--config","/inputs/osv-scanner.toml","--format","json","/src"]
            files={"osv-scanner.toml":(root/"fixtures/osv-scanner.toml").read_bytes()}
        else: return {"status":"blocked","reason":"Unknown fixed white-box scanner","cleanup_confirmed":True}
        result=await self.execute_tool({"tool_id":scanner_id,"phase":"whitebox","source_dir":source_dir,"argv":argv,"input_files":files,"image_pin":image_pin,"offline_db_dir":offline_db_dir},manifest=manifest,cancel_event=cancel_event,request_hook=request_hook,lease_hook=lease_hook)
        if result.get("status")=="completed":
            # The database was hash-checked against the run's tool manifest before this scan (service._scan_source).
            try: result["findings"],result["gaps"]=_parse(scanner_id,result.get("stdout","").encode(),result.get("exit_code"),osv_database_ids(offline_db_dir) if scanner_id=="osv" else frozenset())
            except Exception: result.update(status="execution_error",reason="Scanner output schema or exit status invalid",findings=[])
        caveats=[gap for gap in result.get("gaps",[]) if gap.startswith("Offline OSV results depend")]
        result["limitations"]=caveats
        result["gaps"]=[gap for gap in result.get("gaps",[]) if gap not in caveats]
        result.pop("stdout",None);result.pop("stderr",None)
        return result
