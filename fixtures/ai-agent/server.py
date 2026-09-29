"""Synthetic AI-application fixture: deterministic mock, no real LLM calls."""
from __future__ import annotations

import argparse
import http.client
import json
import os
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

CONTROL = "local-synthetic-control"
MARKER = "[[FIXTURE_REQUEST_EXPORT:doc-b]]"
DOCUMENTS = {
    "doc-a": {"id": "doc-a", "tenant_id": "A", "text": "TENANT_A_RAG_CANARY"},
    "doc-b": {"id": "doc-b", "tenant_id": "B", "text": "TENANT_B_RAG_CANARY"},
    "doc-a-untrusted": {"id": "doc-a-untrusted", "tenant_id": "A", "text": "Synthetic untrusted document. " + MARKER},
}


class FixtureState:
    def __init__(self, mode):
        self.mode = mode
        self.lock = threading.RLock()
        self.reset()

    def reset(self):
        with self.lock:
            self.sessions = {"fixture-ai-a": {"tenant": "A", "memory": []}, "fixture-ai-b": {"tenant": "B", "memory": []}}
            self.events, self.sink = [], []
            self.truncated = False
            self.gateway = None

    def instrument(self, config):
        if not isinstance(config, dict) or set(config) != {"origin", "capability"}:
            raise ValueError("Invalid independent sink configuration")
        parsed = urlsplit(config["origin"])
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port
                or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment
                or not isinstance(config["capability"], str) or not 32 <= len(config["capability"]) <= 100):
            raise ValueError("Only the scoped loopback mock sink is supported")
        self.gateway = dict(config)

    def external_event(self, path, event):
        if self.gateway is None:
            return None
        parsed = urlsplit(self.gateway["origin"])
        connection = http.client.HTTPConnection("127.0.0.1", parsed.port, timeout=3)
        try:
            connection.request("POST", path, json.dumps(event), {
                "Authorization": "Bearer " + self.gateway["capability"], "Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read(4097)
            if response.status != 200 or len(body) > 4096:
                raise ValueError("Independent sink rejected the event")
            return json.loads(body)
        finally:
            connection.close()

    def event(self, run_id, tenant, phase, **fields):
        event = {"run_id": run_id, "actor_tenant": tenant, "phase": phase, "synthetic": True, **fields}
        self.events.append(event)
        self.truncated = self.truncated or len(self.events) > 500
        self.events[:] = self.events[-500:]
        return event


def handler_type(state):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SyntheticAgentFixture/1"

        def log_message(self, *_args):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def reply(self, status, value):
            encoded = json.dumps({"synthetic": True, "model": "deterministic-mock-no-llm", **value}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Fixture-Synthetic", "true")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)

        def body(self):
            length = self.headers.get("Content-Length", "0")
            if not length.isdecimal() or not 0 <= int(length) <= 8192:
                raise ValueError("Request limit")
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                raise ValueError("JSON required")
            value = json.loads(self.rfile.read(int(length)) or b"{}")
            if not isinstance(value, dict):
                raise ValueError("JSON object required")
            return value

        def dispatch(self):
            origin = f"http://127.0.0.1:{self.server.server_port}"
            if self.headers.get("Host") != urlsplit(origin).netloc or self.headers.get("Origin", origin) != origin:
                self.reply(403, {"error": "Fixture host/origin mismatch"})
                return
            url = urlsplit(self.path)
            path = url.path
            if path == "/" and self.command == "GET":
                self.reply(200, {"fixture": "ai-agent", "mode": state.mode,
                                 "notice": "Synthetic retrieval and memory-only mock tool sink. No LLM or external effects."})
                return
            if path.startswith("/__fixture/"):
                if self.headers.get("X-Fixture-Control") != CONTROL:
                    self.reply(403, {"error": "Fixture control header required"})
                    return
                if path == "/__fixture/shutdown" and self.command == "POST":
                    self.body()
                    self.reply(200, {"shutting_down": True})
                    # shutdown() must run outside the serve_forever thread.
                    # This exits the actual interpreter, including when a
                    # Windows venv redirector is our launcher process.
                    threading.Thread(target=self.server.shutdown, daemon=True).start()
                    return
                if path == "/__fixture/reset" and self.command == "POST":
                    self.body()
                    state.reset()
                    self.reply(200, {"reset": True})
                    return
                if path == "/__fixture/instrument" and self.command == "POST":
                    with state.lock:
                        state.instrument(self.body())
                    self.reply(200, {"instrumented": True, "sink_kind": "independent_in_memory_mock"})
                    return
                if path == "/__fixture/state" and self.command == "GET":
                    selected = parse_qs(url.query).get("run_id", [None])[0]
                    with state.lock:
                        events = [e for e in state.events if selected is None or e["run_id"] == selected]
                        sink = [s for s in state.sink if selected is None or s["run_id"] == selected]
                        self.reply(200, {"events": events, "sink": sink, "trace_complete": not state.truncated,
                                         "unauthorized_commits": sum(not s["authorized"] for s in sink),
                                         "session_memory_sizes": {s["tenant"]: len(s["memory"]) for s in state.sessions.values()}})
                    return
                self.reply(404, {"error": "Fixture control route missing"})
                return
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            with state.lock:
                session = state.sessions.get(token)
                if not session or not self.headers.get("Authorization", "").startswith("Bearer "):
                    self.reply(401, {"error": "Active synthetic bearer session required"})
                    return
                tenant = session["tenant"]
                run_id = "mock-" + uuid.uuid4().hex
                if path == "/sessions/reset" and self.command == "POST":
                    self.body()
                    session["memory"].clear()
                    state.event(run_id, tenant, "session_reset")
                    self.reply(200, {"session_reset": True, "memory_size": 0})
                    return
                if path.startswith("/documents/") and self.command == "GET":
                    document_id = path[len("/documents/"):]
                    input_ = {}
                elif path in {"/retrieve", "/agent/run"} and self.command == "POST":
                    input_ = self.body()
                    document_id = input_.get("document_id")
                else:
                    self.reply(404, {"error": "Fixture route missing"})
                    return
                if not isinstance(document_id, str) or document_id not in DOCUMENTS:
                    self.reply(404, {"error": "Synthetic document missing"})
                    return
                document = DOCUMENTS[document_id]
                allowed = document["tenant_id"] == tenant
                if state.mode == "fixed" and not allowed:
                    state.event(run_id, tenant, "retrieval_denied", document_id=document_id)
                    self.reply(403, {"run_id": run_id, "error": "Tenant retrieval boundary denied", "documents": []})
                    return
                state.event(run_id, tenant, "retrieved", document_id=document_id, owner_tenant=document["tenant_id"])
                if path != "/agent/run":
                    self.reply(200, {"run_id": run_id, "documents": [document]})
                    return
                session["memory"].append(document_id)
                session["memory"][:] = session["memory"][-50:]
                # This marker interpreter is deliberately NOT an AI model or an
                # empirical prompt-injection test. It is a repeatable policy fixture.
                proposed = "doc-b" if MARKER in document["text"] else document_id if input_.get("action") == "export" else None
                output = "Mock retrieval completed."
                if proposed:
                    call_id = uuid.uuid4().hex
                    state.external_event("/propose", {"call_id": call_id, "tool_name": "mock_export", "resource_id": proposed})
                    state.event(run_id, tenant, "proposed", tool_name="mock_export", document_id=proposed)
                    target = DOCUMENTS[proposed]
                    authorized = target["tenant_id"] == tenant and input_.get("approved") is True
                    if state.mode == "fixed" and not authorized:
                        state.external_event("/deny", {"call_id": call_id})
                        state.event(run_id, tenant, "denied", tool_name="mock_export", document_id=proposed,
                                    reason="Tenant ownership and explicit fixture approval required")
                        output = "Mock policy denied the export."
                    else:
                        state.external_event("/invoke", {"call_id": call_id})
                        state.event(run_id, tenant, "invoked", tool_name="mock_export", document_id=proposed)
                        # The only effect is appending synthetic text in memory.
                        state.sink.append({"run_id": run_id, "document_id": proposed, "actor_tenant": tenant,
                                           "owner_tenant": target["tenant_id"], "text": target["text"],
                                           "authorized": authorized, "sink_kind": "in_memory_mock"})
                        state.truncated = state.truncated or len(state.sink) > 500
                        state.sink[:] = state.sink[-500:]
                        state.event(run_id, tenant, "committed", tool_name="mock_export", document_id=proposed,
                                    authorized=authorized, sink_kind="in_memory_mock")
                        output = "Mock sink received synthetic text."
                self.reply(200, {"run_id": run_id, "output": output, "retrieved_document_ids": [document_id],
                                 "notice": "Output text is not evidence of tool commitment; inspect the fixture ledger."})

        def do_GET(self):
            try:
                self.dispatch()
            except (ValueError, KeyError, TypeError, json.JSONDecodeError, OSError, http.client.HTTPException):
                self.reply(400, {"error": "Invalid bounded fixture request"})

        do_POST = do_GET
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["vulnerable", "fixed"], default="fixed")
    parser.add_argument("--port", type=int, default=8912)
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("Port must be between 0 and 65535")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_type(FixtureState(args.mode)))
    server.daemon_threads = True
    print(json.dumps({"fixture": "ai-agent", "synthetic": True, "mode": args.mode,
                      "origin": f"http://127.0.0.1:{server.server_port}", "pid": os.getpid(),
                      "model": "deterministic-mock-no-llm"}), flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
