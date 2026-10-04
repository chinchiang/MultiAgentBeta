from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import ValidationError

from .domain import Budget, ModelProfile, RunInput, origin
from .policy import PolicyError
from .service import Engine, report_markdown, report_sarif
from .store import RunNotFound, Store

ROOT=Path(__file__).resolve().parents[2]
LIMITATIONS=[
    "Demo uses synthetic reviewers and fixtures, not real model or target validation.",
    "Live runs require PostgreSQL, three configured models and explicit target IP authorization.",
    "External scanner integrations require a provisioned isolated worker; absent tools never count as passed.",
    "Only observable executed cases are assessed; missing fixtures, identity proof or effect collectors are inconclusive.",
    "Local-only model mode currently requires loopback IP endpoints; a local proxy's upstream behavior is outside this process's control.",
]
SESSION_SECONDS=28800
SECURITY_HEADERS={"X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","X-Frame-Options":"DENY","Cache-Control":"no-store","Content-Security-Policy":"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"}


def create_app(data_dir=None, database_url=None, testing=False, session_token=None):
    # Every local process can reach loopback, so only the operator's startup token opens a new session.
    session_token=session_token or os.getenv("VIBEAUDIT_SESSION_TOKEN") or secrets.token_urlsafe(32)
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,256}",session_token):
        raise ValueError("VIBEAUDIT_SESSION_TOKEN must be 32-256 URL-safe characters (A-Z a-z 0-9 _ -)")
    data_dir=data_dir or os.getenv("VIBEAUDIT_DATA_DIR",str(ROOT/".data"))
    database_url=database_url or os.getenv("VIBEAUDIT_DATABASE_URL")
    store=Store(data_dir,database_url)
    engine=Engine(store,database_url)
    sessions={}
    allowed_origins={"http://127.0.0.1:8000","http://localhost:8000","http://[::1]:8000"}
    allowed_origins|={s.rstrip("/") for s in os.getenv("VIBEAUDIT_UI_ORIGINS","").split(",") if s}
    if testing:
        allowed_origins.add("http://testserver")
    allowed_hosts={s.split("://",1)[1] for s in allowed_origins}
    source_roots=[Path(p).resolve() for p in os.getenv("VIBEAUDIT_SOURCE_ROOTS",str(ROOT/"fixtures")).split(os.pathsep) if p]

    @asynccontextmanager
    async def lifespan(app):
        yield
        for run_id,task in engine.tasks.items():
            if not task.done():
                engine.cancel(run_id)
        pending=[task for task in engine.tasks.values() if not task.done()]
        if pending:
            await asyncio.gather(*pending,return_exceptions=True)
        store.close()

    # The schema is served behind the session; a Swagger page could not load its assets under this CSP.
    app=FastAPI(title="Vibe Audit",version="0.2.0",lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url="/api/openapi.json")
    app.state.store=store
    app.state.engine=engine
    app.state.session_token=session_token
    from .workspace_api import workspace_router
    app.include_router(workspace_router(store,engine,source_roots))

    def current_session(request):
        # Cookies are not isolated by port, so any service on this host that the browser visits receives
        # this one. The CSRF token stays in the page's port-scoped storage: every request needs both.
        session=sessions.get(request.cookies.get("vibeaudit_session",""))
        if not session or session["expires"]<time.monotonic():
            return None
        return session

    def csrf_matches(request,session):
        return secrets.compare_digest(request.headers.get("x-csrf-token","").encode(),session["csrf"].encode())

    async def guard(request):
        if request.headers.get("host","") not in allowed_hosts:
            return JSONResponse({"detail":"Untrusted Host"},status_code=403)
        req_origin=request.headers.get("origin")
        if req_origin and req_origin.rstrip("/") not in allowed_origins:
            return JSONResponse({"detail":"Untrusted Origin"},status_code=403)
        if request.headers.get("sec-fetch-site") in {"cross-site","same-site"}:
            return JSONResponse({"detail":"Cross-site access denied"},status_code=403)
        try:
            declared_length=int(request.headers.get("content-length","0"))
            if declared_length<0:
                raise ValueError
        except ValueError:
            return JSONResponse({"detail":"Invalid Content-Length"},status_code=400)
        if declared_length>512*1024:
            return JSONResponse({"detail":"Request body too large"},status_code=413)
        if request.method in {"POST","PUT","PATCH"}:
            body=bytearray()
            async for chunk in request.stream():
                if len(body)+len(chunk)>512*1024:
                    return JSONResponse({"detail":"Request body too large"},status_code=413)
                body.extend(chunk)
            request._body=bytes(body)
        if request.url.path.startswith("/api/") and request.url.path!="/api/session":
            session=current_session(request)
            if not session:
                return JSONResponse({"detail":"Local session required"},status_code=401)
            # Reads need the token too: the cookie alone would expose evidence, reports and settings.
            if not csrf_matches(request,session):
                return JSONResponse({"detail":"CSRF token required"},status_code=403)
        return None

    @app.middleware("http")
    async def security(request:Request,call_next):
        response=await guard(request)
        if response is None:
            response=await call_next(request)
        # Rejections carry the same headers as the responses they replace.
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.exception_handler(PolicyError)
    async def policy_error(request,exc):
        return JSONResponse({"detail":str(exc)},status_code=409)

    @app.exception_handler(RunNotFound)
    async def not_found(request,exc):
        return JSONResponse({"detail":"Run or artifact not found"},status_code=404)

    @app.exception_handler(ValidationError)
    async def invalid(request,exc):
        # A derived manifest (such as a retest's) can fail validation; that is the caller's input, not a crash.
        return JSONResponse({"detail":"Invalid run configuration: "+"; ".join(str(e.get("msg",""))[:200] for e in exc.errors()[:5])},status_code=422)

    @app.get("/api/session")
    async def session(request:Request):
        startup=request.headers.get("x-vibeaudit-token","")
        if not startup:
            # A reloaded page proves the session with its stored CSRF token; the cookie alone never yields it.
            session=current_session(request)
            if session and csrf_matches(request,session):
                return {"csrf_token":session["csrf"],"mode":"local","limitations":LIMITATIONS}
        if not secrets.compare_digest(startup.encode(),session_token.encode()):
            return JSONResponse({"detail":"Startup token required: open the URL printed when the local service started"},status_code=401)
        moment=time.monotonic()
        for sid in [sid for sid,entry in sessions.items() if entry["expires"]<moment]:
            del sessions[sid]
        sessions.pop(request.cookies.get("vibeaudit_session",""),None)
        sid=secrets.token_urlsafe(32)
        sessions[sid]={"csrf":secrets.token_urlsafe(32),"expires":moment+SESSION_SECONDS}
        response=JSONResponse({"csrf_token":sessions[sid]["csrf"],"mode":"local","limitations":LIMITATIONS})
        response.set_cookie("vibeaudit_session",sid,httponly=True,samesite="strict",max_age=SESSION_SECONDS)
        return response

    @app.get("/api/capabilities")
    async def capabilities(profile: str = "default"):
        # The inventory must describe the runtime profile a run may actually configure,
        # not permanently the default one; an unprovisioned name reports unavailable.
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}",profile):
            raise HTTPException(status_code=422,detail="Invalid runtime profile ID")
        from .adapters import tool_capabilities
        runtime={"postgres":store.postgres,"demo_available":True,"source_roots":[str(p) for p in source_roots],"profile":profile}
        tools=tool_capabilities()
        worker=None
        try:
            from .worker_runtime import WorkerRuntime,load_config
            worker=WorkerRuntime(load_config(profile))
            runtime.update(await worker.capabilities())
            tools=await worker.tool_inventory()
        except Exception:
            # Includes an unreachable lease database: the inventory reports it instead of failing.
            runtime.update(available=False,isolation="unavailable",reason="Configure the Linux isolated worker profile")
        finally:
            if worker:
                worker.leases.close()
        return {"tools":tools,"runtime":runtime,"limitations":LIMITATIONS}

    @app.get("/api/runs")
    async def list_runs():
        # Inventory excludes large snapshots, which stay in the protected evidence service.
        return {"runs":store.list()}

    @app.post("/api/runs",status_code=201)
    async def create_run(data:RunInput):
        if data.mode=="live":
            path=Path(data.source_path).resolve()
            if not any(path==root or path.is_relative_to(root) for root in source_roots):
                raise HTTPException(403,"Source directory is outside configured VIBEAUDIT_SOURCE_ROOTS")
        return engine.create(data)

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id:str):
        return store.get(run_id)

    @app.post("/api/runs/{run_id}/start")
    async def start(run_id:str):
        return engine.start(run_id)

    @app.post("/api/runs/{run_id}/cancel")
    async def cancel(run_id:str):
        return engine.cancel(run_id)

    @app.post("/api/runs/{run_id}/resume")
    async def resume(run_id:str):
        return engine.start(run_id,resume=True)

    @app.get("/api/runs/{run_id}/events")
    async def events(run_id:str,request:Request):
        store.get(run_id)
        try:
            cursor=max(0,int(request.headers.get("last-event-id","0")))
        except ValueError:
            cursor=0
        async def stream():
            nonlocal cursor
            while not await request.is_disconnected():
                run=store.get(run_id)
                for event in run["events"]:
                    if event["seq"]>cursor:
                        cursor=event["seq"]
                        yield f"id: {cursor}\nevent: progress\ndata: {json.dumps(event,ensure_ascii=False)}\n\n"
                # A cancelling run with no task left only changes through an operator reconcile.
                if run["status"] not in {"running","cancelling","created"} or run["status"]=="cancelling" and not engine.executing(run_id):
                    yield "event: done\ndata: {}\n\n"
                    return
                yield ": heartbeat\n\n"
                await asyncio.sleep(.5)
        return StreamingResponse(stream(),media_type="text/event-stream")

    @app.get("/api/runs/{run_id}/evidence/{artifact_id}")
    async def evidence(run_id:str,artifact_id:str):
        run=store.get(run_id)
        record=next((a for a in run["artifacts"] if a["id"]==artifact_id),None)
        if not record:
            raise HTTPException(404,"Evidence not found in this run")
        try:
            return store.evidence(record,run_id)
        except (ValueError,OSError):
            raise HTTPException(409,"Evidence integrity check failed") from None

    @app.get("/api/runs/{run_id}/report")
    async def report(run_id:str,format:str="json"):
        run=store.get(run_id)
        for artifact in run["artifacts"]:
            try:
                store.evidence(artifact,run_id)
            except (ValueError,OSError):
                raise HTTPException(409,"Report blocked: evidence integrity failure") from None
        if format=="markdown":
            return PlainTextResponse(report_markdown(run),media_type="text/markdown")
        if format=="sarif":
            return report_sarif(run)
        if format!="json":
            raise HTTPException(400,"Choose json, markdown or sarif")
        return run

    @app.post("/api/models/probe")
    async def model_probe(request:Request):
        from .providers import probe_model,ProviderError
        try:
            body=await request.json()
            if not isinstance(body,dict):
                raise ValueError
            profile=ModelProfile.model_validate(body["profile"]).model_dump()
            budget=Budget.model_validate(body["budget"]).model_dump()
        except (KeyError,TypeError,ValueError):
            raise HTTPException(422,"A valid profile and explicit probe budget are required") from None
        calls=0
        async def request_hook():
            nonlocal calls
            calls+=1
            if calls>budget["max_model_calls"]:
                raise PolicyError("Probe call budget exhausted")
        policy={"data_policy":body.get("data_policy"),"allowed_model_origins":body.get("allowed_model_origins",[]),"max_tokens":budget["max_tokens"],"timeout_seconds":min(30,budget["max_seconds"]),"request_hook":request_hook}
        try:
            return await probe_model(profile,policy)
        except ProviderError as exc:
            return JSONResponse({"available":False,"status":"blocked","code":exc.code,"detail":str(exc),"usage":exc.usage},status_code=409)

    @app.get("/{path:path}")
    async def frontend(path:str):
        # A mistyped API call must fail as an API error, not succeed with the workbench HTML.
        if path=="api" or path.startswith("api/"):
            return JSONResponse({"detail":"Not Found"},status_code=404)
        dist=ROOT/"frontend"/"dist"
        candidate=(dist/path).resolve()
        if candidate.is_relative_to(dist.resolve()) and candidate.is_file():
            return FileResponse(candidate)
        if (dist/"index.html").exists():
            return FileResponse(dist/"index.html")
        return PlainTextResponse("Frontend not built. Run npm ci && npm run build in frontend, then reload.",status_code=503)

    return app
