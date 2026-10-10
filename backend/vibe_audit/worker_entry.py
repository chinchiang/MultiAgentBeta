"""Trusted independent supervisor and network-none container entry point.

Only this supervisor holds target credentials and a capability. The container
has no network interface except loopback; its local HTTP relay uses a Unix
socket mounted from the supervisor. Controller EOF/lease expiry closes broker
and active sockets before process/container termination. No shell is used.
"""
from __future__ import annotations
import asyncio
import base64
import copy
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import uuid
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
# Two copies (the worker's claim and the supervisor's record) of a task's bounded responses must fit.
MAX_FRAME = 64*1024*1024
# A broker request carries at most a 64 KiB body; nothing larger is buffered before the token check.
BROKER_FRAME = 256*1024
MAX_BODY = 256*1024
# One relayed request, from broker lock to the last response byte, ends within this; the relay waits a little longer.
BROKER_DEADLINE = 25
RELAY_TIMEOUT = 30
# Must equal worker_runtime.CREATE_BUDGET, which sizes the lease around this step.
CREATE_BUDGET = 45
# Must equal worker_runtime.SUPERVISED_FIELDS; this file also runs standalone inside the container.
SUPERVISED_FIELDS = ("broker_observations","cleanup_confirmed","deployment_changed","isolation","lifecycle","task_id","simulated","work_dir_removed","resumed_from_journal")


def docker_api(method,path,timeout=5):
    """Fixed local Docker Engine API; never follows remote contexts/proxies."""
    sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(timeout)
    conn=http.client.HTTPConnection("localhost",timeout=timeout)
    try:
        sock.connect("/var/run/docker.sock");conn.sock=sock
        conn.request(method,"/v1.52"+path)
        response=conn.getresponse();body=response.read(1024*1024+1)
        if len(body)>1024*1024: raise ValueError("Docker response exceeded its bound")
        return response.status,json.loads(body) if body else None
    finally:conn.close();sock.close()


def packed(value):
    return (json.dumps(value,separators=(",",":"),ensure_ascii=False,allow_nan=False)+"\n").encode()


def read_frame(stream,limit=MAX_FRAME):
    raw=stream.readline(limit+1)
    if not raw or len(raw)>limit or not raw.endswith(b"\n"):
        raise ValueError("Missing or oversized IPC frame")
    value=json.loads(raw)
    if not isinstance(value,dict):
        raise ValueError("Invalid IPC frame")
    return value


def clean_env(extra=None):
    keys={"PATH","SYSTEMROOT","WINDIR","TEMP","TMP","HOME","USERPROFILE","LANG","LC_ALL"}
    result={k:v for k,v in os.environ.items() if k.upper() in keys}
    if os.name=="posix":
        result["PATH"]="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    result.update({"PYTHONUNBUFFERED":"1","PYTHONDONTWRITEBYTECODE":"1","DO_NOT_TRACK":"1",
                   "LANGCHAIN_TRACING_V2":"false","LANGSMITH_TRACING":"false","PROMPTFOO_DISABLE_TELEMETRY":"1"})
    result.update(extra or {})
    return result


def terminate_tree(proc):
    if proc is None:
        return True
    try:
        if os.name=="nt":
            import ctypes
            job=getattr(proc,"_vibe_job",None)
            if not job: return False
            if not ctypes.windll.kernel32.TerminateJobObject(job,1): return False
            ctypes.windll.kernel32.CloseHandle(job);proc._vibe_job=None
        else:
            os.killpg(proc.pid,signal.SIGKILL)
    except ProcessLookupError:
        pass
    except Exception:
        return False
    try:
        proc.wait(timeout=5)
        return True
    except Exception:
        return False


def spawn(argv,**kwargs):
    options={"creationflags":0x08000200} if os.name=="nt" else {"start_new_session":True}
    proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,**options,**kwargs)
    if os.name=="nt":
        import ctypes
        from ctypes import wintypes
        class Basic(ctypes.Structure):
            _fields_=[("per_process",ctypes.c_longlong),("per_job",ctypes.c_longlong),("flags",wintypes.DWORD),("min_ws",ctypes.c_size_t),("max_ws",ctypes.c_size_t),("active",wintypes.DWORD),("affinity",ctypes.c_size_t),("priority",wintypes.DWORD),("scheduling",wintypes.DWORD)]
        class Io(ctypes.Structure):
            _fields_=[(name,ctypes.c_ulonglong) for name in ("read_ops","write_ops","other_ops","read_bytes","write_bytes","other_bytes")]
        class Extended(ctypes.Structure):
            _fields_=[("basic",Basic),("io",Io),("process_memory",ctypes.c_size_t),("job_memory",ctypes.c_size_t),("peak_process",ctypes.c_size_t),("peak_job",ctypes.c_size_t)]
        kernel=ctypes.windll.kernel32
        kernel.CreateJobObjectW.restype=wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
        kernel.AssignProcessToJobObject.argtypes=[wintypes.HANDLE,wintypes.HANDLE]
        kernel.TerminateJobObject.argtypes=[wintypes.HANDLE,wintypes.UINT]
        kernel.CloseHandle.argtypes=[wintypes.HANDLE]
        job=kernel.CreateJobObjectW(None,None);limits=Extended();limits.basic.flags=0x2000
        if not job or not kernel.SetInformationJobObject(job,9,ctypes.byref(limits),ctypes.sizeof(limits)) or not kernel.AssignProcessToJobObject(job,int(proc._handle)):
            if job: kernel.CloseHandle(job)
            proc.kill();proc.wait(timeout=5);raise RuntimeError("Windows test process Job Object could not be assigned")
        proc._vibe_job=job
    return proc


class NotSent(ValueError):
    """The request never reached the target, so there is no effect to reconcile."""


class Unusable(ValueError):
    """The target answered, but in a form the broker never relays (redirect, encoding, size, deployment)."""
    def __init__(self,reason,status_code=None):
        super().__init__(reason)
        self.status_code=status_code


# What execute_case and evaluate_oracle read from a case (adapters.py), and what the sequence worker reads from a
# step; worker_view passes nothing else.
WORKER_CASE_FIELDS=("id","adapter","method","path","headers","body","identity","designed_by","side_effects","repetitions","oracle")
# A sequence step's expected answer stays with the supervisor and the console (supervised_sequence): the worker
# sends steps in order and stops when the relay refuses one.
WORKER_STEP_FIELDS=("case_id","method","path","headers","identity","body")


class Supervisor:
    def __init__(self,task):
        from lease import LeaseStore,canonical_hash
        self.task=task
        self.cap=task["capability"]
        self.worker_id=task["worker_id"]
        self.lease=LeaseStore(task.get("database_path"),database_url=task.get("database_url"))
        if canonical_hash(task["spec"])!=self.cap["binding"]["spec_hash"]:
            raise ValueError("Worker specification hash mismatch")
        self.lease.claim(self.cap,self.worker_id)
        self.spec=task["spec"]
        self.manifest=task["manifest"]
        self.revoked=threading.Event()
        self.controller_alive=True
        self.reason=""
        self.policy_blocked=None
        self.deployment_changed=False
        self.sequence_stopped=False
        self.unknown_dispatch=False
        self.output_lock=threading.Lock()
        self.grants={}
        self.grant_lock=threading.Lock()
        self.dispatch_lock=threading.Lock()
        self.sockets=set()
        self.socket_lock=threading.Lock()
        self.sessions={}
        self.sequence=0
        self.server=None
        self.child=None
        self.lifecycle=[]
        self.last_heartbeat=time.monotonic()
        self.broker_observations=[]

    def emit(self,value):
        with self.output_lock:
            try:
                sys.stdout.buffer.write(packed(value));sys.stdout.buffer.flush()
            except (OSError,BrokenPipeError):
                self.controller_alive=False

    def read_controller(self):
        try:
            while True:
                message=read_frame(sys.stdin.buffer)
                if message.get("kind")=="cancel":
                    self.revoke_network("Controller cancelled task")
                elif message.get("kind")=="heartbeat":
                    self.last_heartbeat=time.monotonic()
                elif message.get("kind")=="grant":
                    with self.grant_lock:
                        pending=self.grants.get(message.get("request_id"))
                        if pending:
                            pending[1]=message.get("allow") is True
                            pending[0].set()
        except Exception:
            self.controller_alive=False
            self.revoke_network("Controller pipe closed")

    def revoke_network(self,reason,*,revoke_lease=True):
        with self.socket_lock:
            if self.revoked.is_set():
                return
            self.reason=reason
            self.revoked.set()
            self.lifecycle.append("network_revoked")
            for active in list(self.sockets):
                try: active.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                try: active.close()
                except OSError: pass
            self.sockets.clear()
        with self.grant_lock:
            for pending in self.grants.values(): pending[0].set()
        if revoke_lease:
            try: self.lease.revoke(self.cap["id"],reason)
            except Exception: pass

    def guardian(self):
        from lease import LeaseError
        transient=0
        while not self.revoked.wait(.05):
            if not self.controller_alive or time.monotonic()-self.last_heartbeat>self.cap["ttl_seconds"]:
                self.revoke_network("Controller lease expired or durable authority unavailable")
                return
            try:
                self.lease.validate(self.cap,self.worker_id)
                transient=0
            except LeaseError:
                # A real expiry or revocation of durable authority stops the worker at once.
                self.revoke_network("Controller lease expired or durable authority unavailable")
                return
            except Exception:
                # One transient lease-database error must not kill a mid-flight worker;
                # three consecutive failures mean authority is genuinely unavailable.
                transient+=1
                if transient>=3:
                    self.revoke_network("Durable lease authority unavailable")
                    return

    def sealed_steps(self):
        """The requests this task may send, in order, or None for a tool that chooses its own requests.

        A request_sequence lists them. An http_case task sends each positive control and then its case, once (the
        controller schedules every repetition as its own task), so its order and count are not the worker's choice."""
        if self.spec.get("operation")=="request_sequence":
            return self.spec.get("requests",[])
        if self.spec.get("operation")=="http_case":
            case=(self.spec.get("cases") or [{}])[0]
            return [*[p for p in case.get("preconditions",[]) if isinstance(p,dict)],case]
        return None

    def worker_view(self):
        """The part of an http_case or request_sequence the untrusted worker needs to send it and judge it.

        The worker runs where a hostile target answers; it gets no title, control names or step labels, nothing it
        would only pass on. An http_case keeps its oracle and control texts, since a pass needs the worker's verdict
        and the supervisor's; a sequence worker only sends steps (the supervisor and console judge them) and gets the
        case ID and each step's request, without its expected answer.
        A tool task runs only operator-written cases and keeps its spec."""
        operation=self.spec.get("operation")
        if operation not in {"http_case","request_sequence"}:
            return self.spec
        def control(index,item):
            return {**{k:item[k] for k in ("method","path","headers","identity","expected_status","required_text") if k in item},"name":f"control-{index}"}
        cases=[{**{k:c[k] for k in WORKER_CASE_FIELDS if k in c},
                "preconditions":[control(i,p) for i,p in enumerate([p for p in c.get("preconditions",[]) if isinstance(p,dict)],1)]}
               for c in self.spec.get("cases",[])]
        view={**self.spec,"cases":cases}
        if operation=="request_sequence":
            view["cases"]=[{"id":c.get("id")} for c in self.spec.get("cases",[])]
            # supervised_sequence labels each record from the sealed steps, so the worker needs no label of its own.
            view["requests"]=[{**{k:s[k] for k in WORKER_STEP_FIELDS if k in s},"id":f"step-{i}"} for i,s in enumerate(self.spec.get("requests",[]),1)]
        return view

    def child_task(self,endpoint):
        """What the worker container reads from /inputs/_worker_task.json."""
        return {"spec":self.worker_view(),"broker":endpoint,"broker_token":self.task["broker_token"] if endpoint else None,"backend":self.task["backend"],
                "hard_deadline_unix":time.time()+self.spec["timeout_seconds"]}

    def allowed_request(self,request):
        from adapters import _prepare_request
        method=request.get("method")
        path=request.get("path")
        if (method,path) not in {(r.get("method","GET").upper(),r.get("path")) for r in self.manifest.get("allowed_requests",[])}:
            raise ValueError("Request outside authorized method/path scope")
        cases=self.spec.get("cases",[])
        case_id=request.get("case_id") or (cases[0].get("id") if len(cases)==1 else None)
        case=next((c for c in cases if c.get("id")==case_id),None)
        if not case:
            raise ValueError("Request has no bound case")
        identity=request.get("identity")
        step=None
        steps=self.sealed_steps()
        if steps is not None:
            if self.sequence_stopped: raise ValueError("Sequence stopped at an unmet prerequisite")
            if self.sequence>=len(steps): raise ValueError("Sequence exhausted")
            step=steps[self.sequence]
            if (step.get("method","GET"),step.get("path"),step.get("identity"))!=(method,path,identity):
                raise ValueError("Request does not match the next sealed sequence step")
        else:
            permitted=[case,*[p for p in case.get("preconditions",[]) if isinstance(p,dict)]]
            step=next((p for p in permitted if (p.get("method","GET"),p.get("path"),p.get("identity"))==(method,path,identity)),None)
            if step is None: raise ValueError("Request or identity is not in the sealed case")
        headers=request.get("headers") or {}
        raw=base64.b64decode(request.get("body_b64",""),validate=True)
        if len(raw)>64*1024 or (method in {"GET","HEAD"} and raw): raise ValueError("Request body exceeds scope")
        supplied_headers={k.lower():v for k,v in headers.items()}
        planned_headers={k.lower():v for k,v in step.get("headers",{}).items()}
        if any(supplied_headers.get(k)!=v for k,v in planned_headers.items()):
            raise ValueError("Request headers differ from the sealed step")
        if set(supplied_headers)-set(planned_headers)-{"accept","content-type","user-agent"}:
            raise ValueError("Request contains headers outside its sealed step")
        if self.spec.get("operation")=="request_sequence":
            expected=json.dumps(step["body"]).encode() if step.get("body") is not None else b""
            if raw!=expected: raise ValueError("Sequence request body does not match its sealed step")
        else:
            def unique_object(pairs):
                out={}
                for key,value in pairs:
                    if key in out: raise ValueError("Ambiguous duplicate JSON key")
                    out[key]=value
                return out
            if raw:
                if step.get("body") is None: raise ValueError("The sealed step has no request body")
                received=json.loads(raw,object_pairs_hook=unique_object)
                if json.dumps(received,sort_keys=True,allow_nan=False)!=json.dumps(step.get("body"),sort_keys=True,allow_nan=False):
                    raise ValueError("Request body differs from its sealed case")
                # Equal meaning is not equal bytes: the target gets the sealed body, not the worker's spelling of it.
                raw=json.dumps(step["body"]).encode()
            elif step.get("body") is not None:
                raise ValueError("Sealed request body is missing")
        # The case and its positive controls are what the model wrote; fixture lifecycle steps come from the engine.
        model_step=case.get("designed_by")=="model" and (self.spec.get("operation")!="request_sequence"
            or step.get("id")=="case" or str(step.get("id","")).startswith("control:"))
        if model_step and raw and not any(r.get("model_body") is True and (r.get("method","GET").upper(),r.get("path"))==(method,path)
                                          for r in self.manifest.get("allowed_requests",[])):
            raise ValueError("A model-written body goes only to an endpoint the operator marked model_body")
        # Transport-generated headers are not part of the reviewed request.
        headers=dict(step.get("headers",{}))
        transport={"Content-Type":"application/json"} if raw else None
        if transport: headers.pop("Content-Type",None)
        # This is the last trusted hop before tb-target: model-written headers are checked here against the model
        # vocabulary and the operator's per-endpoint list again, not only by the controller's case gate and the
        # untrusted worker. The supervisor's own Content-Type is transport, not a model choice.
        prepared={"method":method,"path":path,"headers":dict(sorted(headers.items())) if model_step else headers,"body":None,
                  "identity":identity,"designed_by":"model" if model_step else None}
        transient=None
        if isinstance(identity,str) and identity.startswith("session:"):
            transient=self.sessions.get((case_id,identity[8:]))
            if not transient: raise ValueError("Captured session is unavailable")
            prepared["identity"]=None
        method,path,headers,_,secrets=_prepare_request(self.manifest,prepared,transport_headers=transport)
        if transient:
            headers["Authorization"]="Bearer "+transient
            secrets.append(transient)
        return case_id,step,method,path,headers,raw,secrets

    def forward(self,method,path,headers,body,deadline=None):
        from adapters import _origin,_pinned_address
        from lease import LeaseError
        scheme,host,port=_origin(self.manifest)
        try: pinned=_pinned_address(host,port,self.manifest.get("allowed_target_ips",[]))
        except Exception: raise NotSent("Target address could not be resolved within the allowed IPs") from None
        try: self.lease.validate(self.cap,self.worker_id)
        except LeaseError: raise NotSent("Run lease is no longer valid") from None
        address=ipaddress.ip_address(pinned)
        sock=socket.socket(socket.AF_INET6 if address.version==6 else socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(5)
        with self.socket_lock:
            if self.revoked.is_set(): sock.close();raise NotSent("Egress revoked before the request was sent")
            self.sockets.add(sock)
        conn=None
        def expire():
            # Per-operation timeouts let a target trickle bytes forever; the deadline bounds the whole exchange.
            with self.socket_lock:
                try: sock.shutdown(socket.SHUT_RDWR)
                except OSError: pass
        watchdog=threading.Timer(max(0,(deadline or time.monotonic()+BROKER_DEADLINE)-time.monotonic()),expire);watchdog.daemon=True
        watchdog.start()
        try:
            try:
                sock.connect((pinned,port))
                if scheme=="https":
                    secure=ssl.create_default_context().wrap_socket(sock,server_hostname=host,do_handshake_on_connect=False)
                    with self.socket_lock:
                        self.sockets.discard(sock);sock=secure
                        if self.revoked.is_set(): sock.close();raise NotSent("Egress revoked before the request was sent")
                        self.sockets.add(sock)
                    secure.do_handshake()
            except OSError:
                raise NotSent("Target connection failed before the request was sent") from None
            conn=http.client.HTTPConnection(host,port,timeout=5)
            # The TLS socket is set by hand, so the Host header must not name the default HTTPS port.
            conn.default_port=443 if scheme=="https" else 80
            conn.sock=sock
            conn.request(method,path,body=body or None,headers=headers)
            response=conn.getresponse()
            deployment_header=self.manifest.get("deployment_header")
            if deployment_header and response.getheader(deployment_header)!=self.manifest.get("deployment_id"):
                self.policy_blocked="Deployment identity changed or was not present"
                self.deployment_changed=True
                raise Unusable(self.policy_blocked,response.status)
            if 300<=response.status<400: raise Unusable("Target answered with a redirect; redirects are never followed",response.status)
            if response.getheader("Content-Encoding","identity").lower() not in {"","identity"}: raise Unusable("Compressed response denied",response.status)
            length=response.getheader("Content-Length")
            if length is not None and (not length.isdigit() or int(length)>MAX_BODY): raise Unusable("Response size denied",response.status)
            # A HEAD answer and these statuses carry no body, whatever Content-Length announces.
            bodiless=method=="HEAD" or response.status in {204,304}
            data=b"" if bodiless else response.read(MAX_BODY+1)
            if len(data)>MAX_BODY or (not bodiless and length is not None and len(data)!=int(length)): raise Unusable("Incomplete or oversized response",response.status)
            try: text=data.decode("utf-8")
            except UnicodeDecodeError: raise Unusable("Response body is not UTF-8",response.status) from None
            return {"status_code":response.status,"body":text,"complete":True,"peer_ip":pinned,
                    "headers":{"Content-Type":response.getheader("Content-Type","application/json")}}
        finally:
            watchdog.cancel()
            if conn: conn.close()
            with self.socket_lock: self.sockets.discard(sock)
            sock.close()

    def broker_request(self,request):
        deadline=time.monotonic()+BROKER_DEADLINE
        # A request queued behind a slow one must not go out after its relay has given up.
        if not self.dispatch_lock.acquire(timeout=BROKER_DEADLINE/2): raise ValueError("Broker is busy")
        try:
            return self._broker_request(request,deadline)
        finally:
            self.dispatch_lock.release()

    def _broker_request(self,request,deadline):
        if self.revoked.is_set() or request.get("broker_token")!=self.task["broker_token"]:
            raise ValueError("Broker authority unavailable")
        self.lease.validate(self.cap,self.worker_id)
        case_id,step,method,path,headers,body,secrets=self.allowed_request(request)
        rid=uuid.uuid4().hex
        pending=[threading.Event(),False]
        with self.grant_lock: self.grants[rid]=pending
        self.emit({"kind":"request","request_id":rid,"method":method,"path":path,"case_id":case_id,"identity":request.get("identity"),"purpose":step.get("purpose","test")})
        approved=pending[0].wait(max(0,min(10,self.cap["ttl_seconds"],deadline-time.monotonic()-1))) and pending[1]
        with self.grant_lock: self.grants.pop(rid,None)
        if not approved or self.revoked.is_set(): raise ValueError("Controller denied request")
        # The exact record reserved here is also what finish_dispatch must match,
        # so a journaled result can never be attached to a different request.
        sealed_dispatch={"method":method,"path":path,"case_id":case_id,"body_sha256":hashlib.sha256(body).hexdigest()}
        self.lease.reserve_dispatch(self.cap,self.worker_id,rid,sealed_dispatch)
        record={"case_id":case_id,"method":method,"path":path,"identity":request.get("identity"),"purpose":step.get("purpose","test")}
        # Only a read-only step that reached the target has a known outcome when its answer cannot be
        # relayed; any other failure after reservation may have changed the target.
        unsafe=method not in {"GET","HEAD","OPTIONS"} or step.get("side_effects") is True
        try:
            result=self.forward(method,path,headers,body,deadline)
        except Exception as exc:
            known=isinstance(exc,NotSent) or not unsafe and isinstance(exc,(Unusable,OSError,http.client.HTTPException))
            if not known:
                self.unknown_dispatch=True
                self.revoke_network(self.policy_blocked or "Dispatched request has an unknown or invalid result")
                raise
            reason=str(exc) if isinstance(exc,(NotSent,Unusable)) else "Target response was incomplete"
            self.lease.finish_dispatch(self.cap,self.worker_id,rid,sealed_dispatch,{"delivered":not isinstance(exc,NotSent),"reason":reason})
            self.broker_observations.append({**record,"status_code":getattr(exc,"status_code",None),"body":"","peer_ip":None,"complete":False,"denied":reason})
            if self.policy_blocked:
                # Nothing more of this task goes to a deployment other than the declared one.
                self.revoke_network(self.policy_blocked,revoke_lease=False)
            if self.sealed_steps() is not None: self.sequence_stopped=True
            raise
        try:
            capture=step.get("capture_session")
            if capture:
                # A failed capture ends the sequence below; the response itself is known.
                try:
                    value=json.loads(result["body"])
                    for part in capture.get("json_field","").split("."): value=value[part]
                except (ValueError,KeyError,TypeError,IndexError): value=None
                if capture.get("slot") and isinstance(value,str) and value and len(value)<=8192 and all(33<=ord(c)<=126 for c in value):
                    self.sessions[(case_id,capture["slot"])]=value
                    secrets.append(value)
                    result["capture_success"]=True
            secrets.extend(self.sessions.values())
            # A target may reflect another identity's credential; the sandboxed tool must not see that either.
            from adapters import credential_env_allowed,secret_forms
            for profile in self.manifest.get("auth_profiles",[]):
                key=profile.get("credential_env","")
                if credential_env_allowed(key) and os.environ.get(key):
                    secrets.append(os.environ[key])
            for secret in sorted({form for value in secrets for form in secret_forms(value)},key=len,reverse=True):
                result["body"]=result["body"].replace(secret,"[REDACTED_CREDENTIAL]")
            self.lease.finish_dispatch(self.cap,self.worker_id,rid,sealed_dispatch,result)
            self.broker_observations.append({**record,"status_code":result["status_code"],"body":result["body"],"peer_ip":result["peer_ip"],"complete":True,"capture_success":result.get("capture_success") is True,"body_sha256":hashlib.sha256(result["body"].encode()).hexdigest()})
        except Exception:
            self.unknown_dispatch=True
            self.revoke_network("Dispatched request has an unknown or invalid result")
            raise
        if self.sealed_steps() is not None:
            unmet=((step.get("expected_status") is not None and result["status_code"]!=step["expected_status"])
                   or any(text not in result["body"] for text in step.get("required_text",[]))
                   or (step.get("capture_session") and not result.get("capture_success")))
            # Later steps depend on this one, so an unmet prerequisite ends the sequence with a known answer.
            if unmet: self.sequence_stopped=True
            else: self.sequence+=1
        return result

    def start_broker(self):
        owner=self
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.request.settimeout(6)
                try: result={"ok":True,"response":owner.broker_request(read_frame(self.rfile,BROKER_FRAME))}
                except Exception: result={"ok":False,"reason":"Broker denied request or result is unknown"}
                try: self.wfile.write(packed(result))
                except OSError: pass
        if self.task["backend"]=="docker":
            class Server(socketserver.ThreadingUnixStreamServer): daemon_threads=True
            address=str(Path(self.task["broker_dir"])/"broker.sock")
            self.server=Server(address,Handler)
            os.chmod(address,0o666)
            endpoint={"unix":"/broker/broker.sock"}
        else:
            class Server(socketserver.ThreadingTCPServer): daemon_threads=True;allow_reuse_address=True
            self.server=Server(("127.0.0.1",0),Handler)
            endpoint={"tcp":["127.0.0.1",self.server.server_address[1]]}
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        return endpoint

    def docker_control(self,*args):
        try:
            name=self.task["container_name"]
            if args==( "kill",name):method,path="POST",f"/containers/{name}/kill?signal=SIGKILL"
            elif args==("wait",name):method,path="POST",f"/containers/{name}/wait?condition=not-running"
            elif args==("rm","--force",name):method,path="DELETE",f"/containers/{name}?force=true&v=false"
            else:return False
            status,_=docker_api(method,path,timeout=10)
            return status in {200,204,404}
        except Exception: return False

    def run(self):
        threading.Thread(target=self.read_controller,daemon=True).start()
        threading.Thread(target=self.guardian,daemon=True).start()
        try:
            # A white-box scanner sends nothing to a target, so its container gets no broker to ask.
            endpoint=self.start_broker() if self.spec.get("phase")=="blackbox" else None
            child_file=Path(self.task["inputs_dir"])/"_worker_task.json"
            child_file.write_text(json.dumps(self.child_task(endpoint)),encoding="utf-8");os.chmod(child_file,0o444)
        except Exception:
            # No worker or container exists yet, so cleanup is trivially confirmed and nothing was sent.
            try: self.lease.revoke(self.cap["id"],"Supervisor could not prepare the worker")
            except Exception: pass
            self.emit({"kind":"result","result":not_started("Supervisor could not prepare the worker")})
            return
        argv=self.task["argv"]
        outputs=[bytearray(),bytearray()]
        overflow=threading.Event()
        def collect(stream,out):
            while True:
                chunk=stream.read(8192)
                if not chunk: break
                room=max(0,MAX_FRAME-len(out));out.extend(chunk[:room])
                if len(chunk)>room: overflow.set()
        completed=False;cleanup=False
        try:
            if self.revoked.is_set(): raise ValueError("Lease expired before worker start")
            if self.task["backend"]=="docker":
                # Separate create/start so cancellation cannot race a late
                # Docker create into an untracked running container.
                create_argv=list(argv);create_argv[len(self.task["docker_prefix"]) ]="create"
                created=spawn(create_argv,env=clean_env(),cwd=self.task["inputs_dir"])
                try:
                    _,create_error=created.communicate(timeout=min(CREATE_BUDGET,self.spec["timeout_seconds"]))
                    if created.returncode:
                        self.startup_diagnostic=create_error.decode("utf-8",errors="replace")[:1000]
                        raise ValueError("Container creation failed")
                finally:
                    if created.poll() is None: terminate_tree(created)
                if self.revoked.is_set(): raise ValueError("Lease revoked before container start")
                argv=[*self.task["docker_prefix"],"start","--attach",self.task["container_name"]]
            self.child=spawn(argv,env=clean_env(),cwd=self.task["inputs_dir"])
            self.lifecycle.append("worker_started")
            self.emit({"kind":"started","worker_pid":self.child.pid,"container_name":self.task.get("container_name")})
            readers=[threading.Thread(target=collect,args=(stream,out),daemon=True) for stream,out in zip((self.child.stdout,self.child.stderr),outputs)]
            for reader in readers: reader.start()
            # The lease also covers creation and teardown, so the worker's own time limit is enforced here.
            limit=time.monotonic()+self.spec["timeout_seconds"]
            while self.child.poll() is None and not self.revoked.wait(.05):
                if overflow.is_set(): self.revoke_network("Worker IPC output limit exceeded")
                elif time.monotonic()>limit: self.revoke_network("Worker exceeded its time limit")
            completed=self.child.poll()==0 and not self.revoked.is_set() and not overflow.is_set()
            if not completed:
                self.revoke_network(self.reason or "Worker exited without a valid result")
            # The egress barrier is closed before any stop/kill operation.
            if not self.revoked.is_set():
                self.revoke_network("Worker completed; egress closed",revoke_lease=False)
            self.lifecycle.append("worker_termination_started")
            if self.task["backend"]=="docker":
                name=self.task["container_name"]
                if not completed: self.docker_control("kill",name)
                waited=self.docker_control("wait",name)
                removed=self.docker_control("rm","--force",name)
                cleanup=waited and removed
                if self.child.poll() is None: terminate_tree(self.child)
            else:
                # Kill the process group even if its leader already exited, so
                # descendants cannot outlive a nominally successful worker.
                cleanup=terminate_tree(self.child)
            for reader in readers: reader.join(timeout=2)
            self.lifecycle.append("worker_terminated" if cleanup else "cleanup_unknown")
            if not completed or not cleanup:
                # A policy stop is only 'blocked' when every dispatch it interrupted has a known outcome.
                result={"status":"blocked" if self.policy_blocked and not self.unknown_dispatch else "outcome_unknown","reason":self.policy_blocked or self.reason or "Worker cleanup could not be confirmed","cleanup_confirmed":cleanup,"broker_observations":self.broker_observations,"deployment_changed":self.deployment_changed}
                self.lease.revoke(self.cap["id"],result["reason"])
            else:
                result=json.loads(bytes(outputs[0]))
                if not isinstance(result,dict): raise ValueError("Invalid worker result")
                # Fields the supervisor or controller own are only the worker's claim here, so none survive.
                result={k:v for k,v in result.items() if k not in SUPERVISED_FIELDS}
                result.update(broker_observations=self.broker_observations,cleanup_confirmed=True,deployment_changed=self.deployment_changed)
            result.update(isolation="docker_network_none" if self.task["backend"]=="docker" else "process_unisolated_test_only",lifecycle=self.lifecycle,task_id=self.cap["task_id"],simulated=self.task["backend"]!="docker")
            if completed and cleanup:
                # Enrich before journaling, so a result reused from this journal after
                # a controller crash carries its isolation, lifecycle and simulated markers too.
                self.lease.finish_task(self.cap,self.worker_id,result)
            self.emit({"kind":"result","result":result})
            Path(self.task["result_file"]).write_text(json.dumps(result),encoding="utf-8")
        except Exception as exc:
            self.revoke_network("Supervisor or worker result failed")
            if self.task["backend"]=="docker": self.docker_control("kill",self.task["container_name"]);self.docker_control("rm","--force",self.task["container_name"])
            terminate_tree(self.child)
            import traceback
            result={"status":"outcome_unknown","reason":"Supervisor failed; task cannot be replayed","cleanup_confirmed":False,"lifecycle":self.lifecycle,"error_type":type(exc).__name__,"error_location":traceback.extract_tb(exc.__traceback__)[-1].lineno}
            if hasattr(self,"startup_diagnostic"):
                result["startup_diagnostic"]=self.startup_diagnostic
            self.emit({"kind":"result","result":result})
            try: Path(self.task["result_file"]).write_text(json.dumps(result),encoding="utf-8")
            except OSError: pass
        finally:
            self.sessions.clear()
            if self.server: self.server.shutdown();self.server.server_close()
            self.lease.close()


def container_worker(task):
    """Runs in an unprivileged network-none namespace (or explicit test process)."""
    spec=task["spec"]
    # An absolute deadline also bounds a worker if its supervisor dies during
    # daemon operations. Exiting container PID 1 ends its entire PID namespace.
    timer=threading.Timer(max(0,task["hard_deadline_unix"]-time.time()),lambda:os._exit(124));timer.daemon=True;timer.start()
    class Relay(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self): self.forward()
        def do_POST(self): self.forward()
        do_PUT=do_POST
        do_PATCH=do_POST
        do_DELETE=do_POST
        do_HEAD=do_POST
        do_OPTIONS=do_POST
        def forward(self):
            connection=None
            try:
                length=int(self.headers.get("Content-Length","0"))
                if length<0 or length>64*1024 or self.headers.get("Transfer-Encoding"): raise ValueError
                headers={k:v for k,v in self.headers.items() if k.lower() not in {"host","content-length","connection","accept-encoding","x-vibe-case","x-vibe-identity","x-schemathesis-testcaseid"}}
                if any(k.lower() in {"authorization","cookie","proxy-authorization"} for k in headers): raise ValueError
                request={"broker_token":task["broker_token"],"method":self.command,"path":self.path,"headers":headers,
                         "case_id":self.headers.get("X-Vibe-Case"),"identity":self.headers.get("X-Vibe-Identity"),
                         "body_b64":base64.b64encode(self.rfile.read(length)).decode()}
                if task["broker"].get("unix"):
                    connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.settimeout(RELAY_TIMEOUT);connection.connect(task["broker"]["unix"])
                else:
                    connection=socket.create_connection(tuple(task["broker"]["tcp"]),timeout=RELAY_TIMEOUT)
                connection.sendall(packed(request))
                with connection.makefile("rb") as incoming: result=read_frame(incoming)
                if not result.get("ok"): raise ValueError
                response=result["response"];body=response["body"].encode()
                self.send_response(response["status_code"])
                self.send_header("Content-Type",response.get("headers",{}).get("Content-Type","application/json"))
                if response.get("capture_success"): self.send_header("X-Vibe-Capture-Success","true")
                self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
            except Exception:
                try: self.send_error(502,"Broker denied request")
                except OSError: pass
            finally:
                if connection: connection.close()
    server=ThreadingHTTPServer(("127.0.0.1",0),Relay);server.daemon_threads=True
    threading.Thread(target=server.serve_forever,daemon=True).start()
    relay=f"http://127.0.0.1:{server.server_port}"
    inputs=Path("/inputs" if task["backend"]=="docker" else os.getcwd())
    out=Path("/out" if task["backend"]=="docker" else str(inputs.parent/"out"))
    writable=Path("/tmp/vibeaudit-inputs" if task["backend"]=="docker" else str(inputs.parent/"prepared"))
    writable.mkdir(parents=True,exist_ok=True)
    import shutil
    for path in inputs.rglob("*"):
        if path.is_file() and path.name!="_worker_task.json":
            destination=writable/path.relative_to(inputs);destination.parent.mkdir(parents=True,exist_ok=True)
            raw=path.read_bytes()
            if hashlib.sha256(raw).hexdigest()!=spec.get("input_digests",{}).get(path.relative_to(inputs).as_posix()):
                raise ValueError("Worker input changed after capability issuance")
            try: raw=raw.decode("utf-8").replace("{relay_origin}",relay).encode()
            except UnicodeDecodeError: pass
            destination.write_bytes(raw)
    operation=spec.get("operation","tool")
    if operation=="http_case":
        import adapters
        case=copy.deepcopy(spec["cases"][0])
        cid=case["id"]
        # The controller schedules each repetition as its own task; one task sends the case once.
        case["repetitions"]=1
        def remap(value):
            identity=value.pop("identity",None)
            headers=value.setdefault("headers",{});headers["X-Vibe-Case"]=cid
            if identity: headers["X-Vibe-Identity"]=identity
        remap(case)
        for control in case.get("preconditions",[]):
            if isinstance(control,dict): remap(control)
        async def allowed(**_): return None
        result=asyncio.run(adapters.execute_case({"mode":"live","target_url":relay,"relay":True,"allowed_target_ips":["127.0.0.1"],"auth_profiles":[],"run_id":spec.get("run_id")},case,cancel_event=asyncio.Event(),request_hook=allowed))
    elif operation=="request_sequence":
        results=[];sequence_ok=True
        for step in spec.get("requests",[]):
            conn=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=RELAY_TIMEOUT+5)
            headers={**step.get("headers",{}),"X-Vibe-Case":step.get("case_id") or spec["cases"][0]["id"]}
            if step.get("identity"): headers["X-Vibe-Identity"]=step["identity"]
            body=json.dumps(step["body"]).encode() if step.get("body") is not None else None
            if body is not None: headers["Content-Type"]="application/json"
            conn.request(step.get("method","GET"),step["path"],body,headers)
            response=conn.getresponse();text=response.read(MAX_BODY+1).decode();conn.close()
            item={"id":step.get("id"),"status_code":response.status,"body":text,"complete":len(text.encode())<=MAX_BODY,"capture_success":response.getheader("X-Vibe-Capture-Success")=="true"}
            results.append(item)
            # The supervisor stops the sequence at an unmet step and refuses the next request; the relay answers 502.
            if response.status==502:
                sequence_ok=False
                break
        result={"status":"completed" if sequence_ok and len(results)==len(spec.get("requests",[])) else "inconclusive","observations":results,"requests":len(results),"exit_code":0,"stdout":"","stderr":"","artifacts":{}}
    elif operation=="selftest":
        action=spec.get("selftest","echo")
        if action=="spawn_child":
            child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(120)"],env=clean_env(),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            (out/"child_pid.txt").write_text(str(child.pid))
            time.sleep(120)
        elif action=="sleep": time.sleep(float(spec.get("sleep_seconds",120)))
        result={"status":"completed","exit_code":0,"stdout":json.dumps({"pid":os.getpid(),"source_visible":Path("/src").exists(),"broker_offered":task.get("broker") is not None,"uid":os.getuid() if hasattr(os,"getuid") else None,"interfaces":[name for _,name in socket.if_nameindex()]}),"stderr":"","artifacts":{}}
        if action=="forge":
            # A worker that claims fields only its supervisor may set; the supervisor must drop them.
            result.update(deployment_changed=True,work_dir_removed=True,resumed_from_journal=True,simulated=False,isolation="forged",broker_observations=[{"case_id":"forged"}])
    else:
        argv=[s.replace("{relay_origin}",relay).replace("/inputs/",str(writable)+os.sep) for s in spec["argv"]]
        if spec.get("tool_id")=="zap" and task["backend"]=="docker":
            argv[0]="/zap/zap.sh"
        env=clean_env({"VIBEAUDIT_RELAY_ORIGIN":relay,"HOME":"/tmp" if task["backend"]=="docker" else str(writable)})
        if spec.get("tool_id")=="osv": env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"]="/opt/osv-db"
        proc=spawn(argv,cwd=str(writable),env=env)
        limit=spec.get("max_output_bytes",256*1024)
        captures=[bytearray(),bytearray()];exceeded=threading.Event()
        def read_output(stream,dest):
            while True:
                chunk=stream.read(8192)
                if not chunk: break
                available=max(0,limit-len(dest));dest.extend(chunk[:available])
                if len(chunk)>available: exceeded.set();terminate_tree(proc);break
        readers=[threading.Thread(target=read_output,args=(stream,dest),daemon=True) for stream,dest in zip((proc.stdout,proc.stderr),captures)]
        for thread in readers: thread.start()
        code=proc.wait()
        for thread in readers: thread.join(timeout=2)
        artifacts={};total=0
        for name in spec.get("output_files",[]):
            path=out/name
            if path.is_symlink() or not path.is_file() or any(p.is_symlink() for p in path.parents): continue
            if path.stat().st_size>limit: exceeded.set();break
            raw=path.read_bytes()
            total+=len(raw)
            if total>limit: exceeded.set();break
            artifacts[name]=base64.b64encode(raw).decode()
        result={"status":"incomplete" if exceeded.is_set() else "completed","exit_code":code,"stdout":bytes(captures[0]).decode("utf-8",errors="replace"),"stderr":bytes(captures[1]).decode("utf-8",errors="replace"),"artifacts":artifacts,"output_limit_exceeded":exceeded.is_set()}
    server.shutdown();server.server_close()
    sys.stdout.buffer.write(packed(result));sys.stdout.buffer.flush()


def not_started(reason):
    return {"status":"blocked","reason":reason+"; no worker was started","cleanup_confirmed":True,"broker_observations":[],"not_started":True}


if __name__=="__main__":
    if sys.argv[1]=="supervise":
        task=read_frame(sys.stdin.buffer)
        try:
            supervisor=Supervisor(task)
        except Exception:
            # A failed claim, lease-store connection or spec check leaves nothing to clean up; say so, so the
            # controller does not wait for an operator attestation about a worker that never existed.
            sys.stdout.buffer.write(packed({"kind":"result","result":not_started("Supervisor could not claim its capability")}));sys.stdout.buffer.flush()
            raise SystemExit(2)
        supervisor.run()
    elif sys.argv[1]=="worker":
        container_worker(json.loads(Path(sys.argv[2]).read_text(encoding="utf-8")))
    else:
        raise SystemExit("Unknown worker operation")
