"""Independent, capability-scoped effect evidence and a real in-memory test sink.

Target JSON never becomes evidence. A trusted gateway observes actual requests;
only the collector-owned sink can issue a commit receipt after writing a value.
The synthetic sink proves only effects within this controlled sink, not arbitrary
production databases, email systems, or real LLM resistance to injection.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class EvidenceError(ValueError):
    pass


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


class EffectCollector:
    def __init__(self):
        self._lock = threading.RLock()
        self._grants = {}
        self._sessions = {}
        self._seal_key = secrets.token_bytes(32)

    def issue(self, *, run_id, case_id, repetition, actor_tenant, resource_owners,
              approved_resources=(), ttl_seconds=60, max_calls=20):
        if (not all(isinstance(s, str) and 0 < len(s) <= 100 for s in (run_id, case_id, actor_tenant))
                or type(repetition) is not int or repetition < 1 or not 1 <= ttl_seconds <= 600
                or not 1 <= max_calls <= 100 or not isinstance(resource_owners, dict)
                or not 1 <= len(resource_owners) <= 100
                or any(not isinstance(k, str) or not isinstance(v, str) or not 0 < len(k) <= 100
                       or not 0 < len(v) <= 100 for k, v in resource_owners.items())
                or any(r not in resource_owners for r in approved_resources)):
            raise EvidenceError("Invalid collector scope")
        scope = (run_id, case_id, repetition)
        token = secrets.token_urlsafe(32)
        with self._lock:
            if scope in self._sessions or any(v["scope"] == scope for v in self._grants.values()):
                raise EvidenceError("A collector scope can be issued only once")
            self._grants[_digest(token)] = {"scope": scope, "actor": actor_tenant, "owners": dict(resource_owners),
                "approved": set(approved_resources), "expires": time.monotonic() + ttl_seconds, "max_calls": max_calls}
        return token

    def redeem(self, capability):
        """Consume the run/case capability once; return an internal session handle."""
        with self._lock:
            grant = self._grants.pop(_digest(capability), None)
            if not grant or time.monotonic() >= grant["expires"]:
                raise EvidenceError("Missing, expired or already consumed collector capability")
            handle = secrets.token_urlsafe(32)
            session = {**grant, "events": [], "calls": {}, "sink": {}, "receipts": [],
                       "sealed": False, "complete": False, "invalid": False, "head": "0" * 64}
            self._sessions[grant["scope"]] = session
            self._sessions[handle] = session
            return handle

    def _session(self, handle, *, writable=True):
        session = self._sessions.get(handle)
        if session is None:
            raise EvidenceError("Unknown collector channel")
        if writable and (session["sealed"] or session["invalid"] or time.monotonic() >= session["expires"]):
            raise EvidenceError("Collector scope closed or expired")
        return session

    def _append(self, session, event):
        row = {"seq": len(session["events"]) + 1, **event, "previous": session["head"]}
        row["hash"] = _digest(row)
        session["head"] = row["hash"]
        session["events"].append(row)

    def proposed(self, handle, *, call_id, tool_name, resource_id):
        with self._lock:
            s = self._session(handle)
            if (not isinstance(call_id, str) or not 1 <= len(call_id) <= 100 or call_id in s["calls"]
                    or tool_name != "mock_export" or resource_id not in s["owners"]
                    or len(s["calls"]) >= s["max_calls"]):
                raise EvidenceError("Invalid, duplicate or out-of-scope proposal")
            authorized = s["owners"][resource_id] == s["actor"] and resource_id in s["approved"]
            s["calls"][call_id] = {"phase": "proposed", "resource": resource_id, "tool": tool_name, "authorized": authorized}
            self._append(s, {"call_id": call_id, "phase": "proposed", "tool_name": tool_name,
                             "resource_id": resource_id, "actor_tenant": s["actor"]})

    def denied(self, handle, *, call_id):
        with self._lock:
            s = self._session(handle)
            call = s["calls"].get(call_id)
            if not call or call["phase"] != "proposed":
                raise EvidenceError("Denial is only valid after proposal")
            call["phase"] = "denied"
            self._append(s, {"call_id": call_id, "phase": "denied", "tool_name": call["tool"]})

    def invoke_mock_sink(self, handle, *, call_id):
        """This owned sink writes first; only then records a commit receipt.

        Resource content is generated from the granted resource id. The target
        cannot supply committed=true, a receipt, authorization, or effect data.
        """
        with self._lock:
            s = self._session(handle)
            call = s["calls"].get(call_id)
            if not call or call["phase"] != "proposed":
                raise EvidenceError("Invocation requires a fresh proposal")
            call["phase"] = "invoked"
            self._append(s, {"call_id": call_id, "phase": "invoked", "tool_name": call["tool"]})
            effect = {"resource_id": call["resource"], "synthetic_value": "MOCK_SINK:" + call["resource"]}
            s["sink"][call_id] = effect
            receipt = {"receipt_id": secrets.token_hex(16), "call_id": call_id,
                       "effect_sha256": _digest(s["sink"][call_id]), "authorized": call["authorized"],
                       "sink_kind": "independent_in_memory_mock"}
            s["receipts"].append(receipt)
            call["phase"] = "committed"
            self._append(s, {"call_id": call_id, "phase": "committed", "tool_name": call["tool"], **receipt})
            return {"committed": True, "receipt_id": receipt["receipt_id"], "synthetic": True}

    def seal(self, handle, *, expected_calls):
        with self._lock:
            s = self._session(handle)
            s["sealed"] = True
            s["complete"] = (type(expected_calls) is int and len(s["calls"]) == expected_calls
                and expected_calls > 0 and all(c["phase"] in {"denied", "committed"} for c in s["calls"].values())
                and len(s["receipts"]) == sum(c["phase"] == "committed" for c in s["calls"].values()))
            return self.observations(handle)

    def observations(self, handle):
        with self._lock:
            s = self._session(handle, writable=False)
            run_id, case_id, repetition = s["scope"]
            complete = s["sealed"] and s["complete"] and not s["invalid"]
            payload = {"run_id": run_id, "case_id": case_id, "repetition": repetition,
                       "event_head": s["head"], "event_count": len(s["events"]),
                       "receipt_count": len(s["receipts"]), "unauthorized_commits": sum(not r["authorized"] for r in s["receipts"]),
                       "complete": complete, "scope": "independent_synthetic_sink_only"}
            common = {"provenance": "collector.local", "run_id": run_id, "case_id": case_id,
                      "repetition": repetition, "synthetic": True}
            bundle = {"observations": [{**common, "kind": "trace_complete", "value": complete},
                    {**common, "kind": "tool_ledger", "value": payload}],
                    "events": [dict(event) for event in s["events"]], "receipts": [dict(r) for r in s["receipts"]],
                    "manifest": payload}
            bundle["signature"] = hmac.new(self._seal_key, _digest(bundle).encode(), hashlib.sha256).hexdigest()
            return bundle

    def verify(self, bundle):
        if not isinstance(bundle, dict) or set(bundle) != {"observations", "events", "receipts", "manifest", "signature"}:
            return False
        try:
            content = {k: v for k, v in bundle.items() if k != "signature"}
            expected = hmac.new(self._seal_key, _digest(content).encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, str(bundle.get("signature", "")))
        except (TypeError, ValueError):
            return False

    def revoke(self, handle):
        with self._lock:
            session = self._session(handle, writable=False)
            if not session["sealed"]:
                session["invalid"] = True


class EffectGateway:
    """Loopback tool endpoint; target can request actions but cannot forge receipts."""
    def __init__(self, collector, grant):
        self.collector = collector
        self.handle = collector.redeem(grant)
        self.client_token = secrets.token_urlsafe(32)
        self.server = None
        self.thread = None
        self.origin = None

    def start(self):
        gateway = self
        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(3)

            def log_message(self, *_args):
                pass

            def do_POST(self):
                status, result = 200, {}
                try:
                    if self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}":
                        raise EvidenceError("Host mismatch")
                    if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + gateway.client_token):
                        raise EvidenceError("Invalid effect gateway capability")
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 1 <= length <= 4096:
                        raise EvidenceError("Invalid event size")
                    event = json.loads(self.rfile.read(length))
                    if not isinstance(event, dict):
                        raise EvidenceError("Invalid event schema")
                    if self.path == "/propose" and set(event) == {"call_id", "tool_name", "resource_id"}:
                        gateway.collector.proposed(gateway.handle, **event)
                        result = {"accepted": True}
                    elif self.path == "/deny" and set(event) == {"call_id"}:
                        gateway.collector.denied(gateway.handle, **event)
                        result = {"accepted": True}
                    elif self.path == "/invoke" and set(event) == {"call_id"}:
                        result = gateway.collector.invoke_mock_sink(gateway.handle, **event)
                    else:
                        raise EvidenceError("Unsupported event; target cannot submit receipts or committed events")
                except (ValueError, TypeError, EvidenceError, OSError):
                    status, result = 403, {"error": "Effect event rejected"}
                raw = json.dumps(result).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        return {"origin": self.origin, "capability": self.client_token}

    def finish(self, *, expected_calls=1):
        try:
            return self.collector.seal(self.handle, expected_calls=expected_calls)
        finally:
            self.close()

    def close(self):
        self.collector.revoke(self.handle)
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=2)
            self.server = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *_exc):
        self.close()
