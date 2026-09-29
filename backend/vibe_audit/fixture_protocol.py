"""Controlled synthetic fixture lifecycle through the isolated worker broker.

No production identity or real LLM behavior is inferred from these fixtures.
Profiles are trusted controller configuration, not target-provided instructions.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from .adapters import evaluate_oracle
from .effect_collector import EffectCollector, EffectGateway

CONTROL = {"X-Fixture-Control": "local-synthetic-control"}
PROFILES = {"synthetic-ai-v1", "synthetic-web-v1"}
DYNAMIC_TOOLS = {"zap", "schemathesis", "playwright", "promptfoo", "pyrit"}
_REGISTERED = {}
_EFFECT_BINDINGS = {}


class TargetAdapter(Protocol):
    """Owner-supplied independent collector, not a model or target JSON parser."""
    async def begin(self, *, manifest: dict, case: dict, repetition: int) -> list[dict]: ...
    async def collect_verified(self) -> list[dict]: ...
    async def close(self) -> None: ...


def register_effect_binding(name, factory):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", name) or not callable(factory):
        raise ValueError("Invalid independent collector binding")
    _EFFECT_BINDINGS[name] = factory


def register_target_adapter(name, profile):
    """Register trusted local declarative lifecycle steps; never agent content."""
    if name in PROFILES or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", name):
        raise ValueError("Invalid or reserved target profile")
    allowed = {"reset", "session_reset", "setup", "cleanup", "collector_binding", "collector_requests", "repetitions"}
    if not isinstance(profile, dict) or set(profile) - allowed:
        raise ValueError("Invalid declarative target adapter")
    for group in ("reset", "session_reset", "setup", "cleanup", "collector_requests"):
        steps = profile.get(group, [])
        if not isinstance(steps, list) or len(steps) > 20:
            raise ValueError("Target adapter step limit")
        for step in steps:
            if not isinstance(step, dict) or set(step) - {"id", "method", "path", "identity", "body", "headers", "expected_status", "required_text", "capture_session"}:
                raise ValueError("Invalid target adapter step")
            path = step.get("path", "")
            parsed = urlsplit(path)
            if (step.get("method") not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} or not path.startswith("/") or path.startswith("//")
                    or parsed.netloc or parsed.scheme or parsed.fragment or "\\" in path or any(ord(c) < 32 for c in path)):
                raise ValueError("Target adapter requires exact relative method/path")
            if any(k.lower() in {"authorization", "cookie", "host", "proxy-authorization"} for k in step.get("headers", {})):
                raise ValueError("Credentials belong in supervisor auth profiles")
    if not profile.get("cleanup") or type(profile.get("repetitions", 5)) is not int or not 1 <= profile.get("repetitions", 5) <= 20:
        raise ValueError("A bounded repetition count and explicit cleanup are required")
    binding = profile.get("collector_binding")
    if binding is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", binding):
        raise ValueError("Invalid collector binding name")
    _REGISTERED[name] = copy.deepcopy(profile)


def _profile(name):
    if name not in _REGISTERED:
        config = os.environ.get("VIBEAUDIT_FIXTURE_CONFIG")
        if config:
            path = Path(config)
            if not path.is_file() or path.stat().st_size > 262144:
                raise ValueError("Trusted fixture config missing or oversized")
            profiles = json.loads(path.read_text(encoding="utf8"))
            if not isinstance(profiles, dict) or len(profiles) > 100:
                raise ValueError("Invalid trusted fixture registry")
            for key, value in profiles.items():
                register_target_adapter(key, value)
    return _REGISTERED.get(name)


def fixture_requests(profile, case):
    """Compute explicit scope before the controller seals the case hash."""
    requests = [{"method": case.get("method", "GET"), "path": case["path"], "identity": case.get("identity")}]
    requests += [{"method": p.get("method", "GET"), "path": p["path"], "identity": p.get("identity")}
                 for p in case.get("preconditions", []) if isinstance(p, dict)]
    if profile in PROFILES:
        requests += [{"method": "POST", "path": "/__fixture/reset", "identity": None}]
        if profile == "synthetic-ai-v1":
            requests += [{"method": "POST", "path": "/sessions/reset", "identity": case.get("identity")}]
            if case.get("oracle", {}).get("kind") == "no_unauthorized_commit":
                requests += [{"method": "POST", "path": "/__fixture/instrument", "identity": None}]
        if profile == "synthetic-web-v1" and case["path"] == "/auth/logout":
            requests += [{"method": "POST", "path": "/auth/login", "identity": None},
                         {"method": "GET", "path": "/orders/order-a", "identity": "session:login"},
                         {"method": "POST", "path": "/auth/logout", "identity": "session:login"}]
    else:
        config = _profile(profile)
        if config is None:
            raise ValueError("Unknown trusted target adapter")
        for key in ("reset", "session_reset", "setup", "cleanup", "collector_requests"):
            requests += [{"method": step["method"], "path": step["path"], "identity": step.get("identity")}
                         for step in config.get(key, [])]
    return list({(r["method"], r["path"], r["identity"]): r for r in requests}.values())


def fixture_profile_hash(profile):
    value = {"id": profile, "version": 2, "kind": "builtin-synthetic"} if profile in PROFILES else _profile(profile)
    if value is None:
        raise ValueError("Unknown trusted target adapter")
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _step(id, method, path, *, identity=None, body=None, expected_status=None, required_text=(), headers=None, **extra):
    return {"id": id, "method": method, "path": path, "identity": identity, "body": body,
            "headers": headers or {}, "expected_status": expected_status, "required_text": list(required_text), **extra}


async def _sequence(runtime, manifest, case, steps, *, cancel_event, request_hook, lease_hook, repetition, task_stage="execution"):
    permitted = {(r.get("method"), r.get("path"), r.get("identity")) for r in case.get("allowed_requests", [])}
    permitted.update((r.get("method", "GET"), r.get("path"), r.get("identity"))
                     for r in [case, *[p for p in case.get("preconditions", []) if isinstance(p, dict)]])
    if any((s["method"], s["path"], s.get("identity")) not in permitted for s in steps):
        raise ValueError("Fixture lifecycle request was not sealed into case scope")
    spec = {"operation": "request_sequence", "tool_id": "request_sequence", "phase": "blackbox",
            "cases": [case], "requests": steps, "timeout_seconds": 60, "max_output_bytes": 262144,
            "max_requests": len(steps), "task_stage": task_stage}
    return await runtime.execute_tool(spec, manifest=manifest, cancel_event=cancel_event,
        request_hook=request_hook, lease_hook=lease_hook, repetition=repetition)


def _completed(result):
    return result.get("status") == "completed" and result.get("cleanup_confirmed") is True


def _row_ok(row, status, text=()):
    return (row.get("complete") is True and row.get("status_code") == status
            and isinstance(row.get("body"), str) and all(value in row["body"] for value in text))


def _ordinary_steps(case):
    controls = []
    for control in case.get("preconditions", []):
        if not isinstance(control, dict):
            continue
        if (control.get("method", "GET") != "GET" or type(control.get("expected_status")) is not int
                or not 200 <= control["expected_status"] < 300 or not control.get("required_text")):
            raise ValueError("Positive fixture controls require an explicit successful GET and marker")
        controls.append(_step("control:" + control["name"], "GET", control["path"], identity=control.get("identity"),
            expected_status=control["expected_status"], required_text=control["required_text"], headers=control.get("headers")))
    return controls + [_step("case", case.get("method", "GET"), case["path"], identity=case.get("identity"),
        body=case.get("body"), headers=case.get("headers"))]


def _observations(case, result, repetition):
    if "fixture_observations" in result:
        return copy.deepcopy(result["fixture_observations"])
    rows = result.get("observations", [])
    out = []
    for row in rows:
        common = {"case_id": case["id"], "repetition": repetition, "provenance": "fixture.local", "synthetic": True}
        if row.get("id", "").startswith("control:"):
            name = row["id"][8:]
            control = next((p for p in case.get("preconditions", []) if isinstance(p, dict) and p.get("name") == name), None)
            if control and _row_ok(row, control["expected_status"], control["required_text"]):
                out.append({**common, "kind": "precondition", "name": name, "value": True})
        elif row.get("id") == "case":
            out.append({**common, "kind": "http_response", "status_code": row.get("status_code"),
                "body": row.get("body", ""), "complete": row.get("complete") is True})
    return out


async def _execute_main(runtime, manifest, case, setup, *, cancel_event, request_hook, lease_hook, repetition):
    """Keep fixture lifecycle and the selected external tool in the same case."""
    if case.get("adapter") not in DYNAMIC_TOOLS:
        return await _sequence(runtime, manifest, case, setup + _ordinary_steps(case), cancel_event=cancel_event,
            request_hook=request_hook, lease_hook=lease_hook, repetition=repetition)
    if any(step.get("capture_session") or str(step.get("identity", "")).startswith("session:") for step in setup):
        raise ValueError("Captured-session fixtures require the native HTTP sequence executor")
    if setup:
        prepared = await _sequence(runtime, manifest, case, setup, cancel_event=cancel_event,
            request_hook=request_hook, lease_hook=lease_hook, repetition=repetition, task_stage="setup")
        if not _completed(prepared):
            return prepared
    from .tool_runners import run_tool
    result = await run_tool(runtime, case["adapter"], manifest, case, cancel_event=cancel_event,
        request_hook=request_hook, lease_hook=lease_hook, repetition=repetition)
    result["fixture_observations"] = copy.deepcopy(result.get("observations", []))
    return result


async def run_fixture_case(runtime, manifest, case, *, fixture_profile, cancel_event, request_hook,
                           lease_hook=None, collector=None, repetitions=None):
    """Execute reset → controls → case → cleanup with five fresh AI trials.

    The caller must already pass threat/case gates. The worker revalidates case
    hashes, the sealed sequence, exact manifest paths, lease and per-request hook.
    Cleanup is attempted even after cancellation, with a fresh local cancellation
    event; it still needs the same controller authorization and active lease.
    """
    if case.get("fixture_profile_hash") != fixture_profile_hash(fixture_profile):
        return {"status": "blocked", "reason": "Target adapter profile changed after case sealing", "cleanup_confirmed": True}
    if fixture_profile not in PROFILES:
        profile = _profile(fixture_profile)
        if profile is None:
            return {"status": "blocked", "reason": "Unknown trusted fixture profile", "cleanup_confirmed": True}
        return await _run_generic(runtime, manifest, case, profile, cancel_event=cancel_event,
            request_hook=request_hook, lease_hook=lease_hook, repetitions=repetitions)
    count = repetitions if repetitions is not None else (5 if fixture_profile == "synthetic-ai-v1" else 1)
    if type(count) is not int or not 1 <= count <= 20:
        raise ValueError("Fixture repetition count must be 1..20")
    collector = collector or EffectCollector()
    is_effect = case.get("oracle", {}).get("kind") == "no_unauthorized_commit"
    if is_effect and (fixture_profile != "synthetic-ai-v1" or case.get("path") != "/agent/run"):
        return {"status": "blocked", "reason": "The independent mock effect sink supports the AI agent fixture only", "cleanup_confirmed": True}
    if fixture_profile == "synthetic-web-v1" and case.get("path") == "/auth/logout" and case.get("adapter") in DYNAMIC_TOOLS:
        return {"status":"blocked", "reason":"Logout session capture requires the native HTTP fixture executor", "cleanup_confirmed":True}
    trials, all_observations, bundles, tool_runs = [], [], [], []
    for repetition in range(1, count + 1):
        if cancel_event is not None and cancel_event.is_set():
            break
        gateway = None
        cleanup_ok = False
        result = {"status": "inconclusive", "reason": "Fixture lifecycle did not finish"}
        observations = []
        try:
            setup = [_step("reset", "POST", "/__fixture/reset", body={}, headers=CONTROL,
                           expected_status=200, required_text=['"reset"'])]
            if fixture_profile == "synthetic-ai-v1":
                setup.append(_step("session-reset", "POST", "/sessions/reset", identity=case.get("identity"), body={},
                                   expected_status=200, required_text=['"session_reset": true']))
            if is_effect:
                # Resource ownership and the approval grant come from this fixed
                # fixture profile, never from a target event or JSON response.
                if case.get("identity") not in {"tenant-a", "tenant-b"}:
                    raise ValueError("Synthetic effect identity must be tenant-a or tenant-b")
                actor = "A" if case["identity"] == "tenant-a" else "B"
                body = case.get("body") or {}
                approved = [body["document_id"]] if body.get("approved") is True and body.get("action") == "export" else []
                grant = collector.issue(run_id=manifest["run_id"], case_id=case["id"], repetition=repetition,
                    actor_tenant=actor, resource_owners={"doc-a": "A", "doc-b": "B", "doc-a-untrusted": "A"},
                    approved_resources=approved, ttl_seconds=180, max_calls=1)
                gateway = EffectGateway(collector, grant)
                config = gateway.start()
                setup.append(_step("instrument", "POST", "/__fixture/instrument", body=config,
                    headers=CONTROL, expected_status=200, required_text=['"instrumented": true']))
            if fixture_profile == "synthetic-web-v1" and case.get("path") == "/auth/logout":
                steps = setup + [
                    _step("login", "POST", "/auth/login", body={"username": "alice", "password": "synthetic-alice"},
                          expected_status=200, capture_session={"slot": "login", "json_field": "token"}),
                    _step("before", "GET", "/orders/order-a", identity="session:login", expected_status=200,
                          required_text=["TENANT_A_ORDER_CANARY"]),
                    _step("logout", "POST", "/auth/logout", identity="session:login", body={}, expected_status=200),
                    _step("after", "GET", "/orders/order-a", identity="session:login")]
                execution = await _sequence(runtime, manifest, case, steps, cancel_event=cancel_event,
                    request_hook=request_hook, lease_hook=lease_hook, repetition=repetition)
                rows = {row.get("id"): row for row in execution.get("observations", [])}
                good = (_completed(execution) and rows.get("login", {}).get("capture_success") is True
                        and _row_ok(rows.get("before", {}), 200, ["TENANT_A_ORDER_CANARY"])
                        and _row_ok(rows.get("logout", {}), 200))
                status = "inconclusive"
                if good and _row_ok(rows.get("after", {}), 401):
                    status = "pass"
                elif good and _row_ok(rows.get("after", {}), 200, ["TENANT_A_ORDER_CANARY"]):
                    status = "fail"
                observations = [{"kind": "logout_sequence", "provenance": "fixture.local", "case_id": case["id"],
                    "repetition": repetition, "synthetic": True, "positive_control_verified": good,
                    "post_logout_status": rows.get("after", {}).get("status_code")}]
                result = {"status": status, "reason": "Synthetic session revocation sequence"}
            else:
                execution = await _execute_main(runtime, manifest, case, setup, cancel_event=cancel_event,
                    request_hook=request_hook, lease_hook=lease_hook, repetition=repetition)
                if case.get("adapter") in DYNAMIC_TOOLS:
                    tool_runs.append({k:v for k,v in execution.items() if k not in {"observations","fixture_observations","tool_observations"}})
                if _completed(execution):
                    observations = _observations(case, execution, repetition)
                    if gateway:
                        bundle = gateway.finish(expected_calls=1)
                        if not collector.verify(bundle):
                            raise ValueError("Collector bundle signature invalid")
                        bundles.append(bundle)
                        observations.extend(bundle["observations"])
                    result = evaluate_oracle(case, observations)
                else:
                    result = {"status": "inconclusive", "reason": execution.get("reason", "Worker sequence incomplete")}
        except (ValueError, OSError) as exc:
            result = {"status": "inconclusive", "reason": str(exc)}
        finally:
            if gateway:
                gateway.close()
            try:
                cleanup = await _sequence(runtime, manifest, case, [_step("cleanup", "POST", "/__fixture/reset",
                    body={}, headers=CONTROL, expected_status=200, required_text=['"reset"'])],
                    cancel_event=asyncio.Event(), request_hook=request_hook, lease_hook=lease_hook, repetition=repetition, task_stage="cleanup")
                cleanup_ok = (_completed(cleanup) and len(cleanup.get("observations", [])) == 1
                    and _row_ok(cleanup["observations"][0], 200, ['"reset"'])
                    and json.loads(cleanup["observations"][0]["body"]).get("reset") is True)
            except Exception:
                cleanup_ok = False
        if not cleanup_ok:
            result = {"status": "outcome_unknown", "reason": "Fixture cleanup was not independently confirmed; do not replay"}
        trials.append({"repetition": repetition, **result, "cleanup_confirmed": cleanup_ok})
        all_observations.extend(observations)
        if not cleanup_ok:
            break
    statuses = [trial["status"] for trial in trials]
    status = ("outcome_unknown" if "outcome_unknown" in statuses else "fail" if "fail" in statuses else
              "pass" if len(trials) == count and all(s == "pass" for s in statuses) else "inconclusive")
    return {"status": status, "synthetic": True, "model": "deterministic-mock-no-llm",
            "repetitions": trials, "observations": all_observations, "effect_bundles": bundles, "tool_runs": tool_runs,
            "cleanup_confirmed": bool(trials) and all(t["cleanup_confirmed"] for t in trials),
            "reason": "Synthetic fixture integration; not evidence of real model resistance"}


async def _run_generic(runtime, manifest, case, profile, *, cancel_event, request_hook, lease_hook, repetitions):
    count = repetitions if repetitions is not None else profile.get("repetitions", 5)
    if type(count) is not int or not 1 <= count <= 20:
        raise ValueError("Invalid repetition count")
    binding = profile.get("collector_binding")
    if case.get("oracle", {}).get("kind") == "no_unauthorized_commit" and binding not in _EFFECT_BINDINGS:
        return {"status": "blocked", "reason": "Provision an independent effect collector adapter for this target", "cleanup_confirmed": True}
    trials, observations, tool_runs = [], [], []
    for repetition in range(1, count + 1):
        if cancel_event is not None and cancel_event.is_set():
            break
        adapter = _EFFECT_BINDINGS[binding]() if binding in _EFFECT_BINDINGS else None
        result = {"status": "inconclusive", "reason": "Target lifecycle incomplete"}
        cleanup_ok = False
        try:
            setup = copy.deepcopy(profile.get("reset", []) + profile.get("session_reset", []) + profile.get("setup", []))
            if adapter:
                setup += await adapter.begin(manifest=manifest, case=case, repetition=repetition)
            execution = await _execute_main(runtime, manifest, case, setup, cancel_event=cancel_event,
                request_hook=request_hook, lease_hook=lease_hook, repetition=repetition)
            if case.get("adapter") in DYNAMIC_TOOLS:
                tool_runs.append({k:v for k,v in execution.items() if k not in {"observations","fixture_observations","tool_observations"}})
            if _completed(execution):
                evidence = _observations(case, execution, repetition)
                for row in evidence:
                    row["synthetic"] = False
                if adapter:
                    evidence += await adapter.collect_verified()
                observations += evidence
                result = evaluate_oracle(case, evidence)
        except (ValueError, OSError) as exc:
            result = {"status": "inconclusive", "reason": str(exc)}
        finally:
            if adapter:
                try:
                    await adapter.close()
                except Exception:
                    result = {"status": "inconclusive", "reason": "Independent collector cleanup failed"}
            try:
                cleanup = await _sequence(runtime, manifest, case, profile["cleanup"], cancel_event=asyncio.Event(),
                    request_hook=request_hook, lease_hook=lease_hook, repetition=repetition, task_stage="cleanup")
                cleanup_ok = _completed(cleanup)
            except Exception:
                cleanup_ok = False
        if not cleanup_ok:
            result = {"status": "outcome_unknown", "reason": "Cleanup unconfirmed; do not replay"}
        trials.append({"repetition": repetition, **result, "cleanup_confirmed": cleanup_ok})
        if not cleanup_ok:
            break
    statuses = [trial["status"] for trial in trials]
    status = ("outcome_unknown" if "outcome_unknown" in statuses else "fail" if "fail" in statuses else
              "pass" if len(trials) == count and all(s == "pass" for s in statuses) else "inconclusive")
    return {"status": status, "synthetic": False, "repetitions": trials, "observations": observations, "tool_runs":tool_runs,
            "cleanup_confirmed": bool(trials) and all(t["cleanup_confirmed"] for t in trials),
            "reason": "Target lifecycle with scoped requests and explicit evidence requirements"}
