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


def _client_env(manifest):
    from .worker_entry import clean_env
    result=clean_env()
    for profile in manifest.get("auth_profiles",[]):
        key=profile.get("credential_env","")
        if isinstance(key,str) and re.fullmatch(r"VIBEAUDIT_[A-Z0-9_]+",key) and key in os.environ:
            result[key]=os.environ[key]
    return result


def docker_command(*,prefix,image,name,phase,inputs,out,broker,runtime=HERE,source_dir=None,offline_db_dir=None):
    if not IMAGE.fullmatch(image) or not re.fullmatch(r"vibeaudit-worker-[a-f0-9]{32}",name):
        raise WorkerBlocked("An immutable image digest and generated worker name are required")
    if phase not in {"whitebox","blackbox"} or (phase=="blackbox" and source_dir):
        raise WorkerBlocked("Black-box workers cannot receive source mounts")
    uid="65532:65532" if phase=="whitebox" else "65533:65533"
    argv=[*prefix,"run","--name",name,"--pull","never","--network","none","--user",uid,
          "--cap-drop","ALL","--security-opt","no-new-privileges","--read-only","--pids-limit","128",
          "--memory","1g","--memory-swap","1g","--cpus","1","--ulimit","nofile=256:256","--log-driver","none",
          "--tmpfs","/tmp:rw,nosuid,nodev,size=256m,mode=1777","--workdir","/tmp",
          "--env","HOME=/tmp","--env","PYTHONDONTWRITEBYTECODE=1","--env","PROMPTFOO_DISABLE_TELEMETRY=1"]
    for path,target,readonly in [(inputs,"/inputs",True),(out,"/out",False),(broker,"/broker",True),(runtime,"/runtime",True)]:
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
            return {"available":True,"isolation":"docker_network_none","production_ready":True}
        except Exception:
            if 'proc' in locals() and proc.returncode is None:
                proc.kill();await proc.wait()
            return {"available":False,"reason":"Local Linux Docker daemon could not be verified"}

    async def tool_inventory(self):
        from .worker_entry import docker_api
        from urllib.parse import quote
        caps=await self.capabilities()
        rows=[]
        for tool in TOOLS:
            pin=self.images.get(tool) or (self.images.get("worker") if tool in {"playwright","schemathesis","promptfoo","pyrit"} else None)
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
        try:
            spec,files=self._normalize(spec,manifest)
            if cancel_event is not None and cancel_event.is_set(): raise WorkerBlocked("Run was cancelled")
            if lease_hook: await lease_hook()
            image=spec.get("image_pin") or self.images.get(spec["tool_id"]) or self.images.get("worker")
            if self.backend=="docker" and (not isinstance(image,str) or not IMAGE.fullmatch(image)):
                raise WorkerBlocked("Provision a trusted immutable worker image digest")
            private=Path(tempfile.mkdtemp(prefix="w-",dir=self.root));os.chmod(private,0o700)
            inputs=private/"inputs";out=private/"out";broker=private/"broker"
            for directory,mode in [(inputs,0o755),(out,0o777),(broker,0o711)]: directory.mkdir();os.chmod(directory,mode)
            for name,data in files.items():
                path=inputs/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);os.chmod(path,0o444)
            worker_id=uuid.uuid4().hex;name="vibeaudit-worker-"+worker_id
            cases=spec.get("cases",[])
            case_hash=cases[0]["hash"] if len(cases)==1 else canonical_hash({"cases":cases,"source_digest":manifest.get("source_digest")})
            threat_hash=cases[0]["threat_model_hash"] if cases else spec.get("threat_model_hash","offline-whitebox")
            cap=self.leases.issue(run_id=manifest["run_id"],case_hash=case_hash,threat_hash=threat_hash,manifest_hash=canonical_hash(manifest),
                                  max_requests=min(spec.get("max_requests",100),manifest.get("budget",{}).get("max_requests",100)),
                                    ttl_seconds=self.ttl,max_seconds=spec["timeout_seconds"],operation=spec["tool_id"]+(":"+spec["task_stage"] if spec.get("task_stage") in {"setup","cleanup"} else ""),repetition=repetition,spec_hash=canonical_hash(spec))
            prefix=[self.docker,"--host","unix:///var/run/docker.sock"] if self.backend=="docker" else []
            argv=docker_command(prefix=prefix,image=image,name=name,phase=spec["phase"],inputs=inputs,out=out,broker=broker,source_dir=spec.get("source_dir"),offline_db_dir=spec.get("offline_db_dir")) if self.backend=="docker" else [sys.executable,"-I",str(HERE/"worker_entry.py"),"worker",str(inputs/"_worker_task.json")]
            # Only the supervisor receives target credential references; the
            # worker task file contains cases/specification and relay access.
            narrow={k:manifest[k] for k in ("run_id","mode","target_url","allowed_target_ips","allowed_requests","auth_profiles","budget","deployment_id","deployment_header") if k in manifest}
            child_cap={k:v for k,v in cap.items() if k!="renewal_token"}
            initial={"backend":self.backend,"spec":spec,"manifest":narrow,"capability":child_cap,"worker_id":worker_id,
                     "database_path":self.leases.database_path,"database_url":self.leases.database_url,"broker_token":secrets.token_urlsafe(32),
                     "inputs_dir":str(inputs),"broker_dir":str(broker),"result_file":str(private/"supervisor-result.json"),
                     "argv":argv,"docker_prefix":prefix,"container_name":name}
            options={"creationflags":0x08000200} if os.name=="nt" else {"start_new_session":True}
            proc=await asyncio.create_subprocess_exec(sys.executable,"-I",str(HERE/"worker_entry.py"),"supervise",stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,
                                                       env=_client_env(manifest),limit=4*1024*1024+1,**options)
            self.active[cap["task_id"]]={"pid":proc.pid,"capability":cap,"work_dir":str(private)}
            async def send(value):
                proc.stdin.write((json.dumps(value,separators=(",",":"))+"\n").encode());await proc.stdin.drain()
            await send(initial)
            stop=asyncio.Event()
            async def heartbeat():
                while not stop.is_set():
                    try:
                        if cancel_event is not None and cancel_event.is_set(): raise WorkerBlocked("Cancelled")
                        if lease_hook: await lease_hook()
                        self.leases.renew(cap)
                        await send({"kind":"heartbeat"})
                    except Exception:
                        self.leases.revoke(cap["id"],"Controller revoked worker lease")
                        try: await send({"kind":"cancel"})
                        except Exception: pass
                        return
                    try: await asyncio.wait_for(stop.wait(),max(.05,self.ttl/3))
                    except TimeoutError: pass
            beat=asyncio.create_task(heartbeat())
            async def drain_stderr():
                total=0
                while data:=await proc.stderr.read(8192):
                    total+=len(data)
                    if total>256*1024:
                        self.leases.revoke(cap["id"],"Supervisor stderr limit exceeded")
                        return
            errors=asyncio.create_task(drain_stderr())
            result=None
            try:
                deadline=asyncio.get_running_loop().time()+spec["timeout_seconds"]+25
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
                self.leases.revoke(cap["id"],"Controller stopped awaiting worker")
                try: await send({"kind":"cancel"})
                except Exception: pass
            finally:
                stop.set();await beat
                if proc.stdin and not proc.stdin.is_closing(): proc.stdin.close()
                try: await asyncio.wait_for(asyncio.shield(proc.wait()),25)
                except TimeoutError: pass  # Independent guardian remains responsible for teardown.
                errors.cancel();await asyncio.gather(errors,return_exceptions=True)
                self.active.pop(cap["task_id"],None)
            if result is None:
                self.leases.revoke(cap["id"],"No verified supervisor result")
                result={"status":"outcome_unknown","reason":"No complete worker result; do not replay","cleanup_confirmed":False,"task_id":cap["task_id"]}
            for profile in manifest.get("auth_profiles",[]):
                secret=os.environ.get(profile.get("credential_env",""),"")
                if secret:
                    def redact(value):
                        if isinstance(value,str): return value.replace(secret,"[REDACTED_CREDENTIAL]")
                        if isinstance(value,list): return [redact(v) for v in value]
                        if isinstance(value,dict): return {k:redact(v) for k,v in value.items()}
                        return value
                    result=redact(result)
            if isinstance(result.get("artifacts"),dict):
                result["artifacts"]={k:base64.b64decode(v) for k,v in result["artifacts"].items()}
            return result
        except (WorkerBlocked,LeaseError,ValueError,OSError) as exc:
            return {"status":"blocked","reason":str(exc),"cleanup_confirmed":True}

    async def run_case(self,manifest,case,*,cancel_event,request_hook,lease_hook=None,repetition=0):
        return await self.execute_tool({"operation":"http_case","tool_id":"http_case","cases":[case],"phase":"blackbox", "timeout_seconds":min(120,manifest.get("budget",{}).get("max_seconds",120))},manifest=manifest,cancel_event=cancel_event,request_hook=request_hook,lease_hook=lease_hook,repetition=repetition)

    async def run_scanner(self,scanner_id,source_dir,*,manifest,cancel_event,request_hook=None,lease_hook=None,image_pin=None,offline_db_dir=None):
        from .sandbox import _parse
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
            try: result["findings"],result["gaps"]=_parse(scanner_id,result.get("stdout","").encode(),result.get("exit_code"))
            except Exception: result.update(status="execution_error",reason="Scanner output schema or exit status invalid",findings=[])
        caveats=[gap for gap in result.get("gaps",[]) if gap.startswith("Offline OSV results depend")]
        result["limitations"]=caveats
        result["gaps"]=[gap for gap in result.get("gaps",[]) if gap not in caveats]
        result.pop("stdout",None);result.pop("stderr",None)
        return result
