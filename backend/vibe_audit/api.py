from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.exceptions import StarletteHTTPException
from pydantic import ValidationError

from .diagnostics import note_failure
from .domain import Budget, ModelProfile, RunInput
from .messages import PATTERNS, STATUS_ZH, ZH, zh
from .policy import PolicyError
from .service import REPORT_LANGUAGES, Engine, report_markdown, report_sarif
from .settings import DEFAULT_CONSOLE_ORIGINS, ROOT, Settings, startup_token_strong  # noqa: F401  (startup_token_strong: kept for callers)
from .store import RunNotFound, Store

LIMITATIONS=[
    "Demo uses synthetic reviewers and fixtures, not real model or target validation.",
    "Live runs require PostgreSQL, three configured models and explicit target IP authorization.",
    "External scanner integrations require a provisioned isolated worker; absent tools never count as passed.",
    "Only observable executed cases are assessed; missing fixtures, identity proof or effect collectors are inconclusive.",
    "Local-only model mode currently requires loopback IP endpoints; a local proxy's upstream behavior is outside this process's control.",
]
# The same limitations in Traditional Chinese, in the same order, for the console's Chinese interface.
LIMITATIONS_ZH=[
    "示範使用合成審查員與 fixture，並非真實模型或目標的驗證。",
    "實際評估需要 PostgreSQL、三個已設定的模型，以及明確授權的目標 IP。",
    "外部掃描器整合需要已佈建的隔離 worker；缺少的工具絕不算作通過。",
    "只評估可觀測且已執行的案例；缺少 fixture、身分證明或副作用收集器時判為證據不足。",
    "僅本地模型模式目前要求 loopback IP 端點；本地代理對上游的行為不在此程序的控制範圍內。",
]
SESSION_SECONDS=28800
SESSION_IDLE_SECONDS=3600
MAX_SESSIONS=8
# Each wrong startup token in the last window slows the next wrong answer; the right token is never held back,
# so another local process cannot lock the operator out. Guessing resistance comes from the token's entropy.
TOKEN_FAILURE_WINDOW,TOKEN_FAILURE_DELAY,TOKEN_FAILURE_DELAY_MAX=60,0.25,5.0
SECURITY_HEADERS={"X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","X-Frame-Options":"DENY","Cache-Control":"no-store","Content-Security-Policy":"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}


def problem(detail,status_code,headers=None):
    """An error response: `detail` is the stable English text, `detail_zh` the console's Chinese wording when there is one."""
    body={"detail":detail}
    if (chinese:=zh(detail)) is not None:
        body["detail_zh"]=chinese
    return JSONResponse(body,status_code=status_code,headers=headers)


def clock():
    """Session timing; tests replace this, not time.monotonic, which the event loop also reads."""
    return time.monotonic()


async def pause(seconds):
    await asyncio.sleep(seconds)


class _Console:
    """What every route shares: the store and engine, the session table, the trusted origins and hosts, the source roots,
    and the checks each request passes (host, origin, body size, session cookie with its CSRF token)."""

    def __init__(self,settings,store,engine,testing):
        self.store=store
        self.engine=engine
        self.sessions={}
        self.token_failures=deque()
        # Wrong guesses wait in turn, so parallel requests cannot share one delay.
        self.token_gate=asyncio.Lock()
        self.fixed_token=settings.fixed_token
        self.allowed_origins=set(settings.console_origins)
        if testing:
            self.allowed_origins.add("http://testserver")
        # A live target must not be any address this console answers on, the defaults included.
        engine.console_origins=self.allowed_origins|DEFAULT_CONSOLE_ORIGINS
        self.allowed_hosts={s.split("://",1)[1] for s in self.allowed_origins}
        self.source_roots=list(settings.source_roots)

    def current_session(self,request):
        # Cookies are not isolated by port, so any service on this host that the browser visits receives
        # this one. The CSRF token stays in the page's port-scoped storage: every request needs both.
        sid=request.cookies.get("vibeaudit_session","")
        session=self.sessions.get(sid)
        moment=clock()
        if not session or session["expires"]<moment or session["last_seen"]+SESSION_IDLE_SECONDS<moment:
            self.sessions.pop(sid,None)
            return None
        return session

    def csrf_matches(self,request,session):
        return secrets.compare_digest(request.headers.get("x-csrf-token","").encode(),session["csrf"].encode())

    async def guard(self,request):
        if request.headers.get("host","") not in self.allowed_hosts:
            return problem("Untrusted Host",403)
        req_origin=request.headers.get("origin")
        if req_origin and req_origin.rstrip("/") not in self.allowed_origins:
            return problem("Untrusted Origin",403)
        if request.headers.get("sec-fetch-site") in {"cross-site","same-site"}:
            return problem("Cross-site access denied",403)
        try:
            declared_length=int(request.headers.get("content-length","0"))
            if declared_length<0:
                raise ValueError
        except ValueError:
            return problem("Invalid Content-Length",400)
        if declared_length>512*1024:
            return problem("Request body too large",413)
        if request.method in {"POST","PUT","PATCH"}:
            body=bytearray()
            async for chunk in request.stream():
                if len(body)+len(chunk)>512*1024:
                    return problem("Request body too large",413)
                body.extend(chunk)
            request._body=bytes(body)
        if request.url.path.startswith("/api/") and request.url.path!="/api/session":
            session=self.current_session(request)
            if not session:
                return problem("Local session required",401)
            # Reads need the token too: the cookie alone would expose evidence, reports and settings.
            if not self.csrf_matches(request,session):
                return problem("CSRF token required",403)
        return None

    def require_session(self,request:Request):
        """The routes' own check, independent of the middleware's path-prefix test: a route the middleware
        does not cover, or a router mounted elsewhere, still needs the session cookie and its CSRF token."""
        session=self.current_session(request)
        if not session or not self.csrf_matches(request,session):
            raise HTTPException(401,"Local session required")
        session["last_seen"]=clock()
        request.state.session=session
        # Audit records name the session that acted, by a fingerprint that cannot be replayed as a cookie.
        request.state.actor="local_operator:"+session["fingerprint"]
        return session


def _error_handlers(app,console):
    """The request guard as middleware, and the error shapes every route shares."""
    @app.middleware("http")
    async def security(request:Request,call_next):
        response=await console.guard(request)
        if response is None:
            response=await call_next(request)
        # Rejections carry the same headers as the responses they replace.
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request,exc):
        return problem(exc.detail,exc.status_code,exc.headers)

    @app.exception_handler(PolicyError)
    async def policy_error(request,exc):
        return problem(str(exc),409)

    @app.exception_handler(RunNotFound)
    async def not_found(request,exc):
        return problem("Run or artifact not found",404)

    @app.exception_handler(ValidationError)
    async def invalid(request,exc):
        # A derived manifest (such as a retest's) can fail validation; that is the caller's input, not a crash.
        return problem("Invalid run configuration: "+"; ".join(str(e.get("msg",""))[:200] for e in exc.errors()[:5]),422)


def _session_routes(app,api,console):
    """Opening a session with the startup token (or proving one with its CSRF token), and ending sessions."""
    @app.get("/api/session")
    async def session(request:Request):
        startup=request.headers.get("x-vibeaudit-token","")
        if not startup:
            # A reloaded page proves the session with its stored CSRF token; the cookie alone never yields it.
            session=console.current_session(request)
            if session and console.csrf_matches(request,session):
                session["last_seen"]=clock()
                return {"csrf_token":session["csrf"],"mode":"local","limitations":LIMITATIONS,"limitations_zh":LIMITATIONS_ZH}
        moment=clock()
        while console.token_failures and console.token_failures[0]<moment-TOKEN_FAILURE_WINDOW:
            console.token_failures.popleft()
        if not secrets.compare_digest(startup.encode(),app.state.session_token.encode()):
            if startup:
                async with console.token_gate:
                    console.token_failures.append(moment)
                    await pause(min(TOKEN_FAILURE_DELAY_MAX,TOKEN_FAILURE_DELAY*len(console.token_failures)))
            return problem("Startup token required: open the URL printed when the local service started",401)
        for sid in [sid for sid,entry in console.sessions.items() if entry["expires"]<moment or entry["last_seen"]+SESSION_IDLE_SECONDS<moment]:
            del console.sessions[sid]
        console.sessions.pop(request.cookies.get("vibeaudit_session",""),None)
        # The startup token can open console.sessions until the process restarts, but never more than a few at once.
        while len(console.sessions)>=MAX_SESSIONS:
            del console.sessions[min(console.sessions,key=lambda key:console.sessions[key]["last_seen"])]
        sid=secrets.token_urlsafe(32)
        console.sessions[sid]={"csrf":secrets.token_urlsafe(32),"expires":moment+SESSION_SECONDS,"last_seen":moment,
                       "fingerprint":hashlib.sha256(sid.encode()).hexdigest()[:12]}
        response=JSONResponse({"csrf_token":console.sessions[sid]["csrf"],"mode":"local","limitations":LIMITATIONS,"limitations_zh":LIMITATIONS_ZH})
        response.set_cookie("vibeaudit_session",sid,httponly=True,samesite="strict",max_age=SESSION_SECONDS)
        return response

    @api.post("/session/logout")
    async def logout(request:Request):
        """End this session, or with {"all": true} every session. Ending every session also replaces a generated
        startup token (a configured VIBEAUDIT_SESSION_TOKEN stays until the operator changes it and restarts)."""
        raw=await request.body()
        try:
            body=json.loads(raw) if raw else {}
        except ValueError:
            body={}
        everything=isinstance(body,dict) and body.get("all") is True
        rotated=False
        if everything:
            console.sessions.clear()
            if not console.fixed_token:
                app.state.session_token=secrets.token_urlsafe(32)
                app.state.announce_token(app.state.session_token)
                rotated=True
        else:
            console.sessions.pop(request.cookies.get("vibeaudit_session",""),None)
        response=JSONResponse({"ended":"all" if everything else "this","startup_token_rotated":rotated})
        response.delete_cookie("vibeaudit_session")
        return response


def _meta_routes(app,api,console):
    """The schema, the message table and the tool and runtime inventory."""
    @api.get("/openapi.json",include_in_schema=False)
    async def openapi_schema():
        return app.openapi()

    @api.get("/messages")
    async def messages():
        # The console reads the engine's fixed messages in Chinese with the same table the API and reports use.
        return {"exact":ZH,"status":STATUS_ZH,"patterns":[list(pair) for pair in PATTERNS]}

    @api.get("/capabilities")
    async def capabilities(profile: str = "default"):
        # The inventory must describe the runtime profile a run may actually configure,
        # not permanently the default one; an unprovisioned name reports unavailable.
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}",profile):
            raise HTTPException(status_code=422,detail="Invalid runtime profile ID")
        from .adapters import tool_capabilities
        runtime={"postgres":console.store.postgres,"demo_available":True,"source_roots":[str(p) for p in console.source_roots],"profile":profile}
        tools=tool_capabilities()
        worker=None
        try:
            from .worker_runtime import WorkerBlocked,WorkerRuntime,load_config
            worker=WorkerRuntime(load_config(profile))
            runtime.update(await worker.capabilities())
            tools=await worker.tool_inventory()
        except WorkerBlocked as exc:
            # load_config's messages are fixed local text: an unprovisioned profile
            # must not be reported as a generic infrastructure failure.
            runtime.update(available=False,isolation="unavailable",reason=str(exc))
        except Exception as exc:
            # Includes an unreachable lease database: the inventory reports it instead of failing.
            note_failure(f"capabilities of runtime profile {profile}",exc)
            runtime.update(available=False,isolation="unavailable",reason="Configure the Linux isolated worker profile")
        finally:
            if worker:
                worker.leases.close()
        return {"tools":tools,"runtime":runtime,"limitations":LIMITATIONS,"limitations_zh":LIMITATIONS_ZH}


def _run_routes(api,console):
    """Runs: inventory, creation, reads, the operator actions, the progress stream, evidence and reports."""
    @api.get("/runs")
    async def list_runs():
        # The inventory carries each run's summary; events, findings and evidence records come with the run itself.
        return {"runs":await asyncio.to_thread(console.store.summaries)}

    @api.post("/runs",status_code=201)
    async def create_run(data:RunInput):
        if data.mode=="live":
            path=Path(data.source_path).resolve()
            if not any(path==root or path.is_relative_to(root) for root in console.source_roots):
                raise HTTPException(403,"Source directory is outside configured VIBEAUDIT_SOURCE_ROOTS")
            # The run keeps the path that was checked: a later scan reads it literally, so a ".." after a link
            # that is swapped for a directory cannot lead outside the roots.
            data=data.model_copy(update={"source_path":str(path)})
        return console.engine.create(data)

    @api.get("/runs/{run_id}")
    async def get_run(run_id:str):
        # Database reads run off the event loop, so a slow database stalls one request, not every other one.
        return await asyncio.to_thread(console.store.get,run_id)

    @api.post("/runs/{run_id}/start")
    async def start(run_id:str):
        return console.engine.start(run_id)

    @api.post("/runs/{run_id}/cancel")
    async def cancel(run_id:str):
        return console.engine.cancel(run_id)

    @api.post("/runs/{run_id}/resume")
    async def resume(run_id:str):
        return console.engine.start(run_id,resume=True)

    @api.post("/runs/{run_id}/approve-cases")
    async def approve_cases(run_id:str,request:Request):
        """The operator approves the exact sealed case set (its gate receipt) the workbench showed."""
        try:
            body=await request.json()
            receipt=body["receipt"] if isinstance(body,dict) else None
        except (KeyError,TypeError,ValueError):
            receipt=None
        if not isinstance(receipt,str):
            raise HTTPException(422,"Approve with the receipt of the cases you reviewed")
        return console.engine.approve_cases(run_id,receipt,request.state.actor)

    @api.get("/runs/{run_id}/events")
    async def events(run_id:str,request:Request):
        console.store.get(run_id)
        try:
            cursor=max(0,int(request.headers.get("last-event-id","0")))
        except ValueError:
            cursor=0
        async def stream():
            nonlocal cursor
            while not await request.is_disconnected():
                # A session that ended (logout, idle or absolute expiry) stops receiving progress.
                if console.current_session(request) is None:
                    yield "event: expired\ndata: {}\n\n"
                    return
                # Only the events after the cursor are read: the run's body is not loaded whole every half second.
                def poll():
                    return console.store.events_after(run_id,cursor),console.store.summary(run_id)
                events,run=await asyncio.to_thread(poll)
                for event in events:
                    cursor=event["seq"]
                    yield f"id: {cursor}\nevent: progress\ndata: {json.dumps(event,ensure_ascii=False)}\n\n"
                # A cancelling run with no task left only changes through an operator reconcile.
                if run["status"] not in {"running","cancelling","created"} or run["status"]=="cancelling" and not console.engine.executing(run_id):
                    yield "event: done\ndata: {}\n\n"
                    return
                yield ": heartbeat\n\n"
                await asyncio.sleep(.5)
        return StreamingResponse(stream(),media_type="text/event-stream")

    @api.get("/runs/{run_id}/evidence/{artifact_id}")
    async def evidence(run_id:str,artifact_id:str):
        run=console.store.get(run_id)
        record=next((a for a in run["artifacts"] if a["id"]==artifact_id),None)
        if not record:
            raise HTTPException(404,"Evidence not found in this run")
        try:
            return console.store.evidence(record,run_id)
        except (ValueError,OSError):
            raise HTTPException(409,"Evidence integrity check failed") from None

    @api.get("/runs/{run_id}/report")
    async def report(run_id:str,format:str="json",lang:str="en"):
        # lang only changes the Markdown report's wording; JSON and SARIF are data for other tools.
        if lang not in REPORT_LANGUAGES:
            raise HTTPException(400,"Choose lang en or zh-Hant")
        run=console.store.get(run_id)
        for artifact in run["artifacts"]:
            try:
                console.store.evidence(artifact,run_id)
            except (ValueError,OSError):
                raise HTTPException(409,"Report blocked: evidence integrity failure") from None
        if format=="markdown":
            return PlainTextResponse(report_markdown(run,lang),media_type="text/markdown")
        if format=="sarif":
            return report_sarif(run)
        if format!="json":
            raise HTTPException(400,"Choose json, markdown or sarif")
        return run


def _probe_route(api,console):
    """A model endpoint probe under an explicit budget, metered by the same rules as a run's answers."""
    @api.post("/models/probe")
    async def model_probe(request:Request):
        from .answers import ModelAnswers,ProbeDenied
        from .providers import ProviderError
        try:
            body=await request.json()
            if not isinstance(body,dict):
                raise ValueError
            profile=ModelProfile.model_validate(body["profile"]).model_dump()
            budget=Budget.model_validate(body["budget"]).model_dump()
        except (KeyError,TypeError,ValueError):
            raise HTTPException(422,"A valid profile and explicit probe budget are required") from None
        policy={"data_policy":body.get("data_policy"),"allowed_model_origins":body.get("allowed_model_origins",[])}
        try:
            return await ModelAnswers.for_probe(profile,budget,policy,console.engine.model_port).probe(profile)
        except ProviderError as exc:
            return JSONResponse({"available":False,"status":"blocked","code":exc.code,"detail":str(exc),"usage":exc.usage},status_code=409)
        except ProbeDenied as exc:
            return JSONResponse({"available":False,"status":"blocked","code":"request_denied","detail":str(exc),"usage":exc.usage},status_code=409)


def _frontend_route(app):
    """The built console, with API paths kept out of it."""
    @app.get("/{path:path}")
    async def frontend(path:str):
        # A mistyped API call must fail as an API error, not succeed with the workbench HTML.
        if path=="api" or path.startswith("api/"):
            return problem("Not Found",404)
        dist=ROOT/"frontend"/"dist"
        candidate=(dist/path).resolve()
        if candidate.is_relative_to(dist.resolve()) and candidate.is_file():
            return FileResponse(candidate)
        if (dist/"index.html").exists():
            return FileResponse(dist/"index.html")
        return PlainTextResponse("Frontend not built. Run npm ci && npm run build in frontend, then reload.",status_code=503)


def create_app(data_dir=None, database_url=None, testing=False, session_token=None, settings=None):
    """The API, from the settings given or from the environment (the arguments win over it)."""
    # Every local process can reach loopback, so only the operator's startup token opens a new session.
    settings=settings or Settings.from_environ(data_dir=data_dir,database_url=database_url,session_token=session_token)
    store=Store(settings.data_dir,settings.database_url)
    console=_Console(settings,store,Engine(store,settings.database_url),testing)

    @asynccontextmanager
    async def lifespan(app):
        yield
        for run_id,task in console.engine.tasks.items():
            if not task.done():
                console.engine.cancel(run_id)
        pending=[task for task in console.engine.tasks.values() if not task.done()]
        if pending:
            await asyncio.gather(*pending,return_exceptions=True)
        console.store.close()

    # The schema is served behind the session; a Swagger page could not load its assets under this CSP.
    # The schema route is added under the session-checked router below; FastAPI's own would skip its dependencies.
    app=FastAPI(title="Vibe Audit",version="0.2.1",lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
    app.state.store=console.store
    app.state.engine=console.engine
    app.state.session_token=settings.session_token
    # __main__ replaces this to print the full workbench URL when logout of every session issues a new token.
    app.state.announce_token=lambda token:print(f"Vibe Audit: every session ended; new startup token in URL fragment #token={token}",flush=True)
    app.state.sessions=console.sessions

    api=APIRouter(prefix="/api",dependencies=[Depends(console.require_session)])
    from .workspace_api import workspace_router
    app.include_router(workspace_router(store,console.engine,console.source_roots,session=console.require_session))
    _error_handlers(app,console)
    _session_routes(app,api,console)
    _meta_routes(app,api,console)
    _run_routes(api,console)
    _probe_route(api,console)
    app.include_router(api)
    _frontend_route(app)
    return app
