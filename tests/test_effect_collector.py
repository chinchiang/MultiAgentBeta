import copy
import http.client
import json
import unittest
from urllib.parse import urlsplit

from vibe_audit.effect_collector import EffectCollector, EffectGateway, EvidenceError


class EffectCollectorTests(unittest.TestCase):
    def setUp(self):
        self.collector = EffectCollector()

    def grant(self, **kwargs):
        return self.collector.issue(run_id="run", case_id="case", repetition=1,
            actor_tenant="A", resource_owners={"doc-a": "A", "doc-b": "B"}, **kwargs)

    def test_one_time_capability_and_order(self):
        token = self.grant()
        handle = self.collector.redeem(token)
        with self.assertRaises(EvidenceError):
            self.collector.redeem(token)
        with self.assertRaises(EvidenceError):
            self.collector.invoke_mock_sink(handle, call_id="missing")
        self.collector.proposed(handle, call_id="one", tool_name="mock_export", resource_id="doc-b")
        self.collector.denied(handle, call_id="one")
        with self.assertRaises(EvidenceError):
            self.collector.invoke_mock_sink(handle, call_id="one")
        bundle = self.collector.seal(handle, expected_calls=1)
        self.assertTrue(bundle["manifest"]["complete"])
        self.assertEqual(bundle["manifest"]["unauthorized_commits"], 0)
        self.assertEqual([e["phase"] for e in bundle["events"]], ["proposed", "denied"])
        self.assertTrue(self.collector.verify(bundle))
        for key in ("events", "observations", "receipts", "manifest"):
            altered = copy.deepcopy(bundle)
            altered[key] = {} if key == "manifest" else []
            if altered != bundle:
                self.assertFalse(self.collector.verify(altered))

    def test_sink_receipt_follows_real_synthetic_write(self):
        handle = self.collector.redeem(self.grant(approved_resources=["doc-a"]))
        self.collector.proposed(handle, call_id="cross-tenant", tool_name="mock_export", resource_id="doc-b")
        receipt = self.collector.invoke_mock_sink(handle, call_id="cross-tenant")
        bundle = self.collector.seal(handle, expected_calls=1)
        self.assertEqual(bundle["manifest"]["unauthorized_commits"], 1)
        self.assertEqual(bundle["receipts"][0]["receipt_id"], receipt["receipt_id"])
        self.assertFalse(bundle["receipts"][0]["authorized"])
        self.assertEqual([e["phase"] for e in bundle["events"]], ["proposed", "invoked", "committed"])
        with self.assertRaises(EvidenceError):
            self.collector.invoke_mock_sink(handle, call_id="cross-tenant")

    def test_missing_terminal_event_never_complete(self):
        handle = self.collector.redeem(self.grant())
        self.collector.proposed(handle, call_id="one", tool_name="mock_export", resource_id="doc-b")
        self.assertFalse(self.collector.seal(handle, expected_calls=1)["manifest"]["complete"])

    def test_unsealed_gateway_close_revokes_scope(self):
        gateway = EffectGateway(self.collector, self.grant())
        gateway.start()
        gateway.close()
        self.assertFalse(self.collector.observations(gateway.handle)["manifest"]["complete"])
        with self.assertRaises(EvidenceError):
            self.collector.proposed(gateway.handle, call_id="one", tool_name="mock_export", resource_id="doc-b")

    def test_real_gateway_rejects_forged_commit_and_cross_capability(self):
        gateway = EffectGateway(self.collector, self.grant())
        config = gateway.start()
        port = urlsplit(config["origin"]).port
        def request(path, body, token=config["capability"]):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request("POST", path, json.dumps(body), {"Authorization": "Bearer " + token,
                                                       "Content-Type": "application/json"})
            result = conn.getresponse()
            data = json.loads(result.read())
            conn.close()
            return result.status, data
        try:
            self.assertEqual(request("/commit", {"committed": True})[0], 403)
            self.assertEqual(request("/propose", {"call_id":"one", "tool_name":"mock_export", "resource_id":"doc-b"}, "wrong")[0], 403)
            self.assertEqual(request("/propose", {"call_id":"one", "tool_name":"mock_export", "resource_id":"doc-b"})[0], 200)
            self.assertEqual(request("/invoke", {"call_id":"one", "authorized":True})[0], 403)
            self.assertEqual(request("/invoke", {"call_id":"one"})[0], 200)
            bundle = gateway.finish()
            self.assertTrue(self.collector.verify(bundle))
            self.assertEqual(bundle["manifest"]["unauthorized_commits"], 1)
        finally:
            gateway.close()


if __name__ == "__main__":
    unittest.main()
