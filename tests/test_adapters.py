"""Local fixture tests: no cloud credentials and no external target traffic."""
import asyncio
import hashlib
import json
import os
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from vibe_audit import adapters


def case_template():
    return {
        "id": "case-one", "adapter": "http", "method": "GET", "path": "/ok",
        "headers": {}, "body": None, "identity": None, "side_effects": False,
        "preconditions": ["fixture_exists"], "repetitions": 1,
        "oracle": {"kind": "canary_absent", "forbidden_text": ["TENANT_B_CANARY"],
                   "allowed_statuses": [200, 403], "required_observations": ["http_response"],
                   "expected_role": None},
    }


def observation(kind, **fields):
    return {"kind": kind, "provenance": "fixture.local", "case_id": "case-one", **fields}


class OracleTests(unittest.TestCase):
    def setUp(self):
        self.case = case_template()
        # The positive control showed the canary exists, so its absence from the response means something.
        self.control = observation("precondition", name="fixture_exists", value=True,
                                   matched_text_sha256=[hashlib.sha256(b"TENANT_B_CANARY").hexdigest()])
        self.response = observation("http_response", status_code=200, body="safe fixture", complete=True)

    def test_verified_negative_and_leak(self):
        self.assertEqual(adapters.evaluate_oracle(self.case, [self.control, self.response])["status"], "pass")
        self.response["body"] = "TENANT_B_CANARY"
        self.assertEqual(adapters.evaluate_oracle(self.case, [self.control, self.response])["status"], "fail")

    def test_missing_positive_control_is_inconclusive(self):
        self.assertEqual(adapters.evaluate_oracle(self.case, [self.response])["status"], "inconclusive")
        self.case["preconditions"] = []
        self.assertEqual(adapters.evaluate_oracle(self.case, [self.response])["status"], "inconclusive")

    def test_every_executor_needs_a_control_that_showed_the_canary(self):
        # Fixture and tool runs label controls fixture.local; they get no exemption from the canary proof.
        for control in [{**self.control, "matched_text_sha256": []},
                        {**self.control, "matched_text_sha256": [hashlib.sha256(b"order-a").hexdigest()]},
                        {**self.control, "value": False}]:
            self.assertEqual(adapters.evaluate_oracle(self.case, [control, self.response])["status"], "inconclusive")

    def test_target_claims_are_not_trusted(self):
        self.control["provenance"] = "target.json"
        self.assertEqual(adapters.evaluate_oracle(self.case, [self.control, self.response])["status"], "inconclusive")

    def test_other_case_observations_are_not_trusted(self):
        self.response["case_id"] = "a-different-case"
        self.assertEqual(adapters.evaluate_oracle(self.case, [self.control, self.response])["status"], "inconclusive")

    def test_missing_requirements_truncation_and_error_status(self):
        for field, value in [("complete", False), ("status_code", 500)]:
            response = {**self.response, field: value}
            self.assertEqual(adapters.evaluate_oracle(self.case, [self.control, response])["status"], "inconclusive")
        self.case["oracle"]["required_observations"] = []
        self.assertEqual(adapters.evaluate_oracle(self.case, [self.control, self.response])["status"], "inconclusive")

    def test_configured_identity_does_not_prove_actual_role(self):
        self.case["oracle"]["expected_role"] = "reader"
        self.assertEqual(adapters.evaluate_oracle(self.case, [self.control, self.response])["status"], "inconclusive")
        identity = observation("identity_verified", role="reader", value=True)
        self.assertEqual(adapters.evaluate_oracle(self.case, [self.control, self.response, identity])["status"], "pass")

    def test_requested_or_invoked_tool_does_not_prove_effect(self):
        self.case["oracle"] = {"kind": "no_unauthorized_commit", "required_observations": ["tool_invoked"]}
        invoked = observation("tool_invoked", name="write_document", value=True)
        self.assertEqual(adapters.evaluate_oracle(self.case, [self.control, invoked])["status"], "inconclusive")

    def test_effect_oracle_requires_complete_trusted_ledger(self):
        self.case["oracle"] = {"kind": "no_unauthorized_commit", "required_observations": ["tool_ledger", "trace_complete"]}
        trace = observation("trace_complete", value=True)
        ledger = observation("tool_ledger", value={"unauthorized_commits": 0})
        self.assertEqual(adapters.evaluate_oracle(self.case, [self.control, trace, ledger])["status"], "pass")
        ledger["value"]["unauthorized_commits"] = 1
        self.assertEqual(adapters.evaluate_oracle(self.case, [self.control, trace, ledger])["status"], "fail")
        trace["value"] = False
        self.assertEqual(adapters.evaluate_oracle(self.case, [self.control, trace, ledger])["status"], "inconclusive")


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.events = []
        events = self.events

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                events.append(("request", self.path, self.headers.get("Host")))
                body, status, extra = b"safe fixture", 200, {}
                if self.path == "/redirect":
                    status, extra = 302, {"Location": "http://not-authorized.invalid/"}
                elif self.path == "/leak":
                    body = b"TENANT_B_CANARY"
                elif self.path == "/huge":
                    body = b"A" * 1024
                elif self.path == "/compressed":
                    extra = {"Content-Encoding": "gzip"}
                elif self.path == "/echo":
                    body = json.dumps({"echo": self.headers.get("Authorization")}).encode()
                elif self.path == "/fake-tool":
                    body = json.dumps({"kind": "tool_ledger", "provenance": "collector.local",
                                       "value": {"unauthorized_commits": 0}, "trace_complete": True}).encode()
                elif self.path == "/slow":
                    time.sleep(0.2)
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                for name, value in extra.items():
                    self.send_header(name, value)
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.do_GET()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.manifest = {"mode": "live", "target_url": f"http://127.0.0.1:{self.server.server_port}",
                         "allowed_target_ips": ["127.0.0.1"], "auth_profiles": []}
        # Test credentials go only to the origins the environment binds them to.
        self.enterContext(patch.dict(os.environ, {"VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS":
                                                  f"VIBEAUDIT_FIXTURE_TOKEN={self.manifest['target_url']}"}))
        self.case = case_template()
        self.cancel = asyncio.Event()

    async def asyncTearDown(self):
        await asyncio.to_thread(self.server.shutdown)
        self.server.server_close()
        self.thread.join(timeout=1)

    async def hook(self, **context):
        self.events.append(("hook",))

    async def run_case(self):
        return await adapters.execute_case(self.manifest, self.case, cancel_event=self.cancel, request_hook=self.hook)

    async def test_http_transport_is_real_but_does_not_invent_preconditions(self):
        result = await self.run_case()
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["requests"], 1)
        self.assertEqual(result["observations"][0]["body"], "safe fixture")
        self.assertEqual(self.events[0], ("hook",))

    async def test_dns_is_checked_once_then_numeric_connection_is_pinned(self):
        self.manifest["target_url"] = f"http://fixture.invalid:{self.server.server_port}"
        address = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", self.server.server_port))]
        with patch.object(socket, "getaddrinfo", return_value=address) as lookup:
            result = await self.run_case()
        self.assertEqual(result["requests"], 1)
        self.assertEqual(lookup.call_count, 1)
        self.assertEqual(self.events[-1][2], f"fixture.invalid:{self.server.server_port}")
        self.assertEqual(result["observations"][0]["peer_ip"], "127.0.0.1")

    async def test_mixed_authorized_and_unauthorized_dns_answer_is_blocked(self):
        self.manifest["target_url"] = f"http://fixture.invalid:{self.server.server_port}"
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 80)) for ip in ["127.0.0.1", "192.0.2.1"]]
        with patch.object(socket, "getaddrinfo", return_value=addresses):
            result = await self.run_case()
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(self.events, [])

    async def test_metadata_and_link_local_targets_are_never_contacted(self):
        # Even listed beside the real target, a metadata or link-local address blocks the case.
        for allowed in [["127.0.0.1", "169.254.169.254"], ["127.0.0.1", "fe80::1"], ["127.0.0.1", "::ffff:169.254.169.254"]]:
            self.manifest["allowed_target_ips"] = allowed
            result = await self.run_case()
            self.assertEqual((result["status"], result["requests"]), ("blocked", 0), allowed)
        self.manifest["target_url"] = "http://metadata.invalid"
        self.manifest["allowed_target_ips"] = ["169.254.169.254"]
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]
        with patch.object(socket, "getaddrinfo", return_value=answer):
            result = await self.run_case()
        self.assertEqual((result["status"], result["requests"]), ("blocked", 0))
        self.assertEqual(self.events, [])

    async def test_rebinding_between_repetitions_is_blocked(self):
        self.manifest["target_url"] = f"http://fixture.invalid:{self.server.server_port}"
        self.case["repetitions"] = 2
        addresses = [[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 80))] for ip in ["127.0.0.1", "192.0.2.1"]]
        with patch.object(socket, "getaddrinfo", side_effect=addresses):
            result = await self.run_case()
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["requests"], 1)
        self.assertEqual([e[0] for e in self.events], ["hook", "request"])

    async def test_redirect_is_never_followed(self):
        self.case["path"] = "/redirect"
        result = await self.run_case()
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["requests"], 1)
        self.assertEqual([e[0] for e in self.events], ["hook", "request"])

    async def test_redirect_after_state_changing_request_is_outcome_unknown(self):
        # The target already processed the POST; reporting it as blocked would invite a replay.
        self.case.update({"method": "POST", "path": "/redirect", "body": {"message": "fixture"}})
        result = await self.run_case()
        self.assertEqual(result["status"], "outcome_unknown")
        self.assertEqual(result["requests"], 1)

    async def test_unsafe_methods_count_as_state_changing_despite_case_claim(self):
        for method in ["PUT", "PATCH", "DELETE"]:
            self.case = {**case_template(), "method": method, "body": {}, "side_effects": False}
            result = await self.run_case()
            self.assertEqual(result["status"], "blocked", method)
            self.assertEqual(result["requests"], 0)
        self.assertEqual(self.events, [])

    async def test_a_model_post_counts_as_state_changing_inside_the_worker_too(self):
        # Only an operator may declare a POST free of side effects; the controller holds a model case to that, and so
        # does the worker, which has the case's designed_by.
        self.case = {**case_template(), "method": "POST", "body": {"message": "fixture"}, "side_effects": False, "designed_by": "model"}
        result = await self.run_case()
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["requests"], 0)
        self.assertEqual(self.events, [])

    async def test_the_worker_reads_whether_a_post_changes_state_from_the_cases_request_plan(self):
        # The plan decided who wrote the case (the model) when it was sealed; the worker's copy says nothing of it.
        self.case = {**case_template(), "method": "POST", "body": {"message": "fixture"}, "side_effects": False,
                     "request_plan": {"version": 1, "steps": [{"id": "case", "phase": "case", "source": "model", "read_only": False}]}}
        result = await self.run_case()
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["requests"], 0)
        self.assertEqual(self.events, [])

    async def test_hook_precedes_each_request(self):
        self.case["repetitions"] = 3
        result = await self.run_case()
        self.assertEqual(result["requests"], 3)
        self.assertEqual([e[0] for e in self.events], ["hook", "request"] * 3)

    async def test_missing_hook_or_cancel_prevents_target_request(self):
        result = await adapters.execute_case(self.manifest, self.case, cancel_event=self.cancel)
        self.assertEqual(result["status"], "blocked")
        self.cancel.set()
        result = await self.run_case()
        self.assertEqual(result["requests"], 0)
        self.assertEqual(self.events, [])

    async def test_budget_rejection_is_not_leaked_or_sent(self):
        async def deny(**context):
            raise ValueError("do-not-return-secret")
        result = await adapters.execute_case(self.manifest, self.case, cancel_event=self.cancel, request_hook=deny)
        self.assertEqual(result["requests"], 0)
        self.assertNotIn("do-not-return-secret", json.dumps(result))
        self.assertEqual(self.events, [])

    async def test_cancel_during_hook_prevents_target_request(self):
        async def cancel_now(**context):
            self.cancel.set()
        result = await adapters.execute_case(self.manifest, self.case, cancel_event=self.cancel, request_hook=cancel_now)
        self.assertEqual(result["requests"], 0)
        self.assertEqual(self.events, [])

    async def test_oversized_or_compressed_response_cannot_pass(self):
        for path in ["/huge", "/compressed"]:
            self.case["path"] = path
            with patch.object(adapters, "MAX_RESPONSE_BYTES", 32):
                result = await self.run_case()
            self.assertEqual(result["status"], "inconclusive")
            self.assertEqual(result["observations"], [])

    async def test_bounded_timeout_does_not_pass(self):
        self.case["path"] = "/slow"
        started = time.monotonic()
        with patch.object(adapters, "REQUEST_TIMEOUT_SECONDS", 0.05):
            result = await self.run_case()
        self.assertIn(result["status"], {"execution_error", "inconclusive"})
        self.assertLess(time.monotonic() - started, 0.5)

    async def test_lost_state_changing_response_is_outcome_unknown(self):
        self.case.update({"method": "POST", "path": "/slow", "body": {}})
        with patch.object(adapters, "REQUEST_TIMEOUT_SECONDS", 0.05):
            result = await self.run_case()
        self.assertEqual(result["status"], "outcome_unknown")
        self.assertEqual(result["requests"], 1)

    async def test_auth_uses_prefixed_environment_and_redacts_echo(self):
        self.case.update({"path": "/echo", "identity": "reader"})
        self.manifest["auth_profiles"] = [{"id": "reader", "credential_env": "VIBEAUDIT_FIXTURE_TOKEN"}]
        with patch.dict(os.environ, {"VIBEAUDIT_FIXTURE_TOKEN": "fixture-private-token"}):
            result = await self.run_case()
        serialized = json.dumps(result)
        self.assertNotIn("fixture-private-token", serialized)
        self.assertIn("REDACTED_CREDENTIAL", serialized)
        self.manifest["auth_profiles"][0]["credential_env"] = "OTHER_TOKEN"
        result = await self.run_case()
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["requests"], 0)
        # The tool's own settings are never sent to a target, under their own name or an alias.
        for name, environ in [("VIBEAUDIT_DATABASE_URL", {"VIBEAUDIT_DATABASE_URL": "postgresql://u:p@db/x"}),
                              ("VIBEAUDIT_FIXTURE_TOKEN", {"VIBEAUDIT_FIXTURE_TOKEN": "s" * 40, "VIBEAUDIT_SESSION_TOKEN": "s" * 40})]:
            self.manifest["auth_profiles"][0]["credential_env"] = name
            with patch.dict(os.environ, environ):
                result = await self.run_case()
            self.assertEqual((result["status"], result["requests"]), ("blocked", 0))

    async def test_target_credential_goes_only_to_its_bound_origin(self):
        self.case.update({"path": "/echo", "identity": "reader"})
        self.manifest["auth_profiles"] = [{"id": "reader", "credential_env": "VIBEAUDIT_FIXTURE_TOKEN"}]
        target = self.manifest["target_url"]
        for binding in ["", "VIBEAUDIT_OTHER_TOKEN=" + target, "VIBEAUDIT_FIXTURE_TOKEN=http://127.0.0.1:1",
                        "VIBEAUDIT_FIXTURE_TOKEN=https://" + target.split("://")[1], "VIBEAUDIT_FIXTURE_TOKEN=" + target + "/api",
                        "VIBEAUDIT_FIXTURE_TOKEN=" + target + ",broken"]:
            with patch.dict(os.environ, {"VIBEAUDIT_FIXTURE_TOKEN": "fixture-private-token",
                                         "VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS": binding}):
                result = await self.run_case()
            self.assertEqual((result["status"], result["requests"]), ("blocked", 0), binding)
        self.assertNotIn("request", [event[0] for event in self.events])
        # A name may be bound to several origins; the default port is the same origin written either way.
        with patch.dict(os.environ, {"VIBEAUDIT_FIXTURE_TOKEN": "fixture-private-token",
                                     "VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS": f"VIBEAUDIT_FIXTURE_TOKEN=http://127.0.0.1:1, VIBEAUDIT_FIXTURE_TOKEN={target}/"}):
            result = await self.run_case()
        self.assertEqual(result["requests"], 1)
        self.assertEqual(adapters.target_credential_origins({"VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS": "VIBEAUDIT_A=http://Example.com:80"}),
                         {"VIBEAUDIT_A": {("http", "example.com", 80)}})
        with self.assertRaises(adapters.AdapterBlocked):
            adapters.target_credential_origins({"VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS": "VIBEAUDIT_DATABASE_URL=http://127.0.0.1:1"})

    async def test_model_credential_is_never_a_target_credential(self):
        self.case.update({"path": "/echo", "identity": "reader"})
        self.manifest["auth_profiles"] = [{"id": "reader", "credential_env": "VIBEAUDIT_FIXTURE_TOKEN"}]
        environ = {"VIBEAUDIT_FIXTURE_TOKEN": "model-key-value", "VIBEAUDIT_MODEL_KEY": "model-key-value"}
        # The same variable, or another variable holding the same key, reaches no target.
        for model_env in ["VIBEAUDIT_FIXTURE_TOKEN", "VIBEAUDIT_MODEL_KEY"]:
            self.manifest["models"] = [{"id": "reviewer-a", "credential_env": model_env}]
            with patch.dict(os.environ, environ):
                self.assertEqual(adapters.shared_credentials(self.manifest), ["VIBEAUDIT_FIXTURE_TOKEN"])
                result = await self.run_case()
            self.assertEqual((result["status"], result["requests"]), ("blocked", 0))
            self.assertNotIn(("request", "/echo"), [event[:2] for event in self.events])
        with patch.dict(os.environ, {**environ, "VIBEAUDIT_MODEL_KEY": "another-key"}):
            self.assertEqual(adapters.shared_credentials(self.manifest), [])
            result = await self.run_case()
        self.assertEqual(result["requests"], 1)

    async def test_ai_http_does_not_promote_response_claims_to_ledger(self):
        self.case.update({"adapter": "ai_http", "path": "/fake-tool", "method": "POST", "body": {"message": "fixture"}, "preconditions": []})
        self.case["oracle"] = {"kind": "no_unauthorized_commit", "required_observations": ["tool_ledger", "trace_complete"]}
        result = await self.run_case()
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual([o["kind"] for o in result["observations"]], ["http_response"])

    async def test_real_positive_control_supports_vulnerable_fail_and_fixed_pass(self):
        self.case["preconditions"] = [{"name": "fixture_exists", "method": "GET", "path": "/leak", "identity": None,
                                      "expected_status": 200, "required_text": ["TENANT_B_CANARY"]}]
        scoped = []
        async def scope_hook(**context):
            scoped.append(context)
        for path, status in [("/leak", "fail"), ("/ok", "pass")]:
            self.case["path"] = path
            result = await adapters.execute_case(self.manifest, self.case, cancel_event=self.cancel, request_hook=scope_hook)
            self.assertEqual(result["status"], status)
            self.assertEqual(result["requests"], 2)
            self.assertEqual(result["observations"][0]["kind"], "precondition")
            self.assertNotIn("body", result["observations"][0])
            self.assertEqual(scoped[-2:], [{"method": "GET", "path": "/leak"}, {"method": "GET", "path": path}])

    async def test_model_designed_control_headers_use_fixed_vocabularies(self):
        control = {"name": "fixture_exists", "method": "GET", "path": "/leak", "identity": None,
                   "expected_status": 200, "required_text": ["TENANT_B_CANARY"], "headers": {"If-None-Match": '"snapshot-text"'}}
        self.case.update(designed_by="model", path="/ok", preconditions=[control])
        self.manifest["allowed_requests"] = [{"method": "GET", "path": "/leak", "model_headers": {"If-None-Match": ["*"]}}]
        result = await self.run_case()
        self.assertEqual((result["status"], result["requests"]), ("blocked", 0))
        control["headers"] = {"If-None-Match": "*"}
        result = await self.run_case()
        self.assertEqual((result["status"], result["requests"]), ("pass", 2))
        # The same control on an endpoint the operator listed nothing for sends nothing.
        self.manifest["allowed_requests"] = [{"method": "GET", "path": "/leak"}]
        result = await self.run_case()
        self.assertEqual((result["status"], result["requests"]), ("blocked", 0))

    async def test_failed_positive_control_does_not_send_main_request(self):
        self.case["preconditions"] = [{"name": "fixture_exists", "method": "GET", "path": "/ok",
                                      "expected_status": 200, "required_text": ["TENANT_B_CANARY"]}]
        self.case["path"] = "/leak"
        result = await self.run_case()
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["requests"], 1)
        self.assertEqual([e[1] for e in self.events if e[0] == "request"], ["/ok"])

    async def test_health_control_does_not_prove_sensitive_fixture_exists(self):
        self.case["preconditions"] = [{"name": "health", "method": "GET", "path": "/ok",
                                      "expected_status": 200, "required_text": ["safe fixture"]}]
        result = await self.run_case()
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["requests"], 2)

    async def test_positive_control_cannot_bypass_request_scope(self):
        self.case["preconditions"] = [{"name": "fixture_exists", "method": "GET", "path": "/leak",
                                      "expected_status": 200, "required_text": ["TENANT_B_CANARY"]}]
        async def scope_hook(*, method, path):
            if path != "/ok":
                raise ValueError("path outside signed scope")
        result = await adapters.execute_case(self.manifest, self.case, cancel_event=self.cancel, request_hook=scope_hook)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["requests"], 0)
        self.assertEqual(self.events, [])

    async def test_redaction_does_not_turn_observed_leak_into_pass(self):
        self.manifest["auth_profiles"] = [{"id": "reader", "credential_env": "VIBEAUDIT_FIXTURE_TOKEN"}]
        self.case.update({"path": "/echo", "identity": "reader"})
        self.case["oracle"]["forbidden_text"] = ["fixture-private-token"]
        self.case["preconditions"] = [{"name": "fixture_exists", "method": "GET", "path": "/echo", "identity": "reader",
                                      "expected_status": 200, "required_text": ["fixture-private-token"]}]
        with patch.dict(os.environ, {"VIBEAUDIT_FIXTURE_TOKEN": "fixture-private-token"}):
            result = await self.run_case()
        self.assertEqual(result["status"], "fail")
        self.assertNotIn("fixture-private-token", json.dumps(result))
        self.assertEqual(adapters.evaluate_oracle(self.case, result["observations"])["status"], "fail")

    async def test_scope_header_path_and_side_effect_abuse_are_blocked(self):
        changes = [{"headers": {"Host": "evil.invalid"}}, {"headers": {"Authorization": "Bearer inline"}},
                   {"headers": {"X-API-Key": "inline"}}, {"path": "//evil.invalid/"},
                   {"path": "https://evil.invalid/"}, {"path": "/ok\r\nInjected: x"}, {"side_effects": True}]
        for change in changes:
            self.case = {**case_template(), **change}
            result = await self.run_case()
            self.assertEqual(result["status"], "blocked", change)
            self.assertEqual(result["requests"], 0)
        self.assertEqual(self.events, [])


class TargetAddressTests(unittest.TestCase):
    def test_refused_target_addresses(self):
        import ipaddress
        refused = ["169.254.169.254", "169.254.1.1", "fe80::1", "fd00:ec2::254", "100.100.100.200", "0.0.0.0", "::",
                   "224.0.0.1", "ff02::1", "255.255.255.255", "240.0.0.1", "::ffff:169.254.169.254", "fec0::1",
                   # NAT64 and 6to4 spellings of the metadata address.
                   "64:ff9b::a9fe:a9fe", "64:ff9b:1::a9fe:a9fe", "2002:a9fe:a9fe::1"]
        allowed = ["127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1", "10.0.0.5", "192.168.1.5", "172.16.0.9",
                   "100.64.0.1", "93.184.216.34", "2001:db8::1", "fd12:3456::1", "64:ff9b::5db8:d822"]
        self.assertEqual([a for a in refused if not adapters.target_ip_refused(ipaddress.ip_address(a))], [])
        self.assertEqual([a for a in allowed if adapters.target_ip_refused(ipaddress.ip_address(a))], [])

    def test_control_plane_target_names_the_endpoint_without_secrets(self):
        console = ["http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000"]
        database = "postgresql://vibeaudit:db-password@localhost/vibeaudit"
        def hit(target, ips, endpoints):
            return adapters.control_plane_target({"target_url": target, "allowed_target_ips": ips}, endpoints)
        self.assertEqual(hit("http://127.0.0.1:8000", ["127.0.0.1"], console), "127.0.0.1:8000")
        # Every loopback address reaches the same listener, under any name.
        self.assertEqual(hit("http://staging.test:8000", ["127.0.0.2"], console[1:2]), "localhost:8000")
        self.assertEqual(hit("http://[::1]:5432", ["::1"], [database]), "localhost:5432")
        self.assertNotIn("db-password", hit("http://127.0.0.1:5432", ["127.0.0.1"], [database]))
        self.assertEqual(hit("https://db.internal:5432", ["10.0.0.9"], ["postgresql://u:p@10.0.0.9/x"]), "10.0.0.9:5432")
        self.assertEqual(hit("https://db.internal:5432", ["10.0.0.8"], ["postgresql://u:p@db.internal:5432/x"]), "db.internal:5432")
        # Another port, another host, or a Unix-socket database is not the control plane.
        self.assertIsNone(hit("http://127.0.0.1:9000", ["127.0.0.1"], [*console, database]))
        self.assertIsNone(hit("http://10.0.0.5:8000", ["10.0.0.5"], console))
        self.assertIsNone(hit("http://127.0.0.1:5432", ["127.0.0.1"], ["postgresql:///vibeaudit?host=/run/postgresql", ""]))
        with self.assertRaisesRegex(adapters.AdapterBlocked, "explicit IP addresses"):
            hit("http://127.0.0.1:9000", ["localhost"], console)
        # No allowlist yet is no hit; an unparsable endpoint is skipped, not the end of the search.
        self.assertIsNone(adapters.control_plane_target({"target_url": "http://127.0.0.1:8000"}, console))
        self.assertEqual(hit("http://127.0.0.1:8000", ["127.0.0.1"], ["http://[::1", *console]), "127.0.0.1:8000")
        self.assertEqual(hit("http://[::1]:8000", ["::1"], ["http://[::1]:8000"]), "[::1]:8000")

    def test_pinned_address_resolves_names_inside_the_allowlist_only(self):
        calls = []
        def fake_getaddrinfo(host, port, **kwargs):
            calls.append((host, port, kwargs))
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.5", port))]
        with patch.object(adapters.socket, "getaddrinfo", fake_getaddrinfo):
            self.assertEqual(adapters._pinned_address("example.test", 443, ["203.0.113.5", "203.0.113.6"]), "203.0.113.5")
            with self.assertRaisesRegex(adapters.AdapterBlocked, "outside the exact target IP allowlist"):
                adapters._pinned_address("example.test", 443, ["203.0.113.6"])
        self.assertEqual(calls, [("example.test", 443, {"type": socket.SOCK_STREAM})] * 2)
        # A literal address never touches DNS, and the lowest address of a set is the one dialled.
        with patch.object(adapters.socket, "getaddrinfo", side_effect=AssertionError("no DNS for a literal")):
            self.assertEqual(adapters._pinned_address("10.0.0.5", 80, ["10.0.0.5"]), "10.0.0.5")
            with self.assertRaisesRegex(adapters.AdapterBlocked, "outside the exact target IP allowlist"):
                adapters._pinned_address("10.0.0.7", 80, ["10.0.0.5"])
        for allowed, message in [("10.0.0.5", "explicit IP addresses"), ([10], "explicit IP addresses"), (["10.0.0.0/8"], "explicit IP addresses"),
                                 ([], "No target IP addresses"), (["169.254.169.254"], "cloud metadata")]:
            with self.assertRaisesRegex(adapters.AdapterBlocked, message):
                adapters._pinned_address("10.0.0.5", 80, allowed)

    def test_one_of_matches_whole_listed_values_only(self):
        pattern = adapters._one_of(["a", "b.c"])
        self.assertTrue(pattern.fullmatch("b.c") and pattern.fullmatch("a"))
        self.assertIsNone(pattern.fullmatch("bxc"))
        self.assertIsNone(pattern.fullmatch("a|b.c"))


class StateChangeTests(unittest.TestCase):
    def test_side_effects_claim_cannot_make_unsafe_method_read_only(self):
        for method in ["PUT", "PATCH", "DELETE"]:
            self.assertTrue(adapters.state_changing({"method": method, "side_effects": False}))
        # POST also serves search and chat: only an operator-written case may declare it read-only.
        self.assertFalse(adapters.state_changing({"method": "POST", "side_effects": False}))
        self.assertTrue(adapters.state_changing({"method": "POST", "side_effects": False}, operator_case=False))
        self.assertFalse(adapters.state_changing({"method": "GET", "side_effects": False}, operator_case=False))
        self.assertTrue(adapters.state_changing({"method": "GET", "side_effects": True}))


class ToolCapabilityTests(unittest.TestCase):
    def test_detected_cli_does_not_claim_ready(self):
        with patch.object(adapters.shutil, "which", return_value="/untrusted/bin/tool"):
            capabilities = adapters.tool_capabilities()
        scanners = [c for c in capabilities if c["id"] in {"semgrep", "osv", "gitleaks", "zap", "schemathesis", "playwright", "promptfoo", "pyrit"}]
        self.assertTrue(all(c["cli_detected"] and not c["available"] for c in scanners))

    def test_capability_list_is_fixed(self):
        capabilities = adapters.tool_capabilities()
        self.assertEqual([c["id"] for c in capabilities], ["semgrep", "osv", "gitleaks", "zap", "schemathesis", "playwright", "promptfoo", "pyrit", "synthetic_demo", "tool_effect_collector"])
        self.assertEqual({(c["available"], c["status"], c["implemented"]) for c in capabilities[:8]}, {(False, "implemented_requires_runtime", True)})
        self.assertEqual({c["detail"] for c in capabilities[:8]}, {"Adapter 已實作；尚未配置可驗證的 Linux 隔離執行環境與固定工具映像。"})
        self.assertEqual({c["detail_en"] for c in capabilities[:8]}, {"Adapter implemented; no verifiable isolated Linux runtime or pinned tool image is configured yet."})
        self.assertEqual(capabilities[8], {"id": "synthetic_demo", "available": True, "status": "synthetic_only", "implemented": True,
                                           "detail": "可執行本地合成流程；不會呼叫真實模型或驗證其偵測品質。",
                                           "detail_en": "Runs the local synthetic flow; it calls no real model and does not verify detection quality."})
        self.assertEqual(capabilities[9], {"id": "tool_effect_collector", "available": False, "status": "target_binding_required", "implemented": True,
                                           "detail": "獨立事件及副作用收集器已實作；實際目標必須配置可信 binding，無觀測時不判定通過。",
                                           "detail_en": "Independent event and side-effect collector implemented; a real target needs a trusted binding, and nothing passes without an observation."})

    def test_every_capability_explains_itself_in_chinese_and_english(self):
        # The console shows detail or detail_en depending on the language the operator chose.
        for capability in adapters.tool_capabilities():
            self.assertRegex(capability["detail"], "[\u4e00-\u9fff]")
            self.assertTrue(capability["detail_en"].isascii() and capability["detail_en"].strip())


if __name__ == "__main__":
    unittest.main()
