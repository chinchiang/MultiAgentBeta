"""Boundaries added after the 2026-10-06 VibeSec G4 architecture and identity review."""
import base64
import sys

import pytest

from vibe_audit import adapters
from vibe_audit.adapters import AdapterBlocked, _prepare_request, canonical_model_headers, case_headers_allowed
from vibe_audit.worker_entry import Supervisor


@pytest.mark.parametrize("headers,allowed", [
    ({"Accept": "application/json", "Accept-Language": "zh-TW"}, True),
    # Letter case, a repeat under other case and the order of names are all model choices that can encode text.
    ({"accept": "application/json"}, False),
    ({"ACCEPT": "application/json"}, False),
    ({"Accept": "*/*", "aCcEpT": "text/html"}, False),
    ({"Accept-Language": "zh-TW", "Accept": "application/json"}, False),
])
def test_model_header_names_have_one_spelling_and_one_order(headers, allowed):
    assert case_headers_allowed(headers, model_designed=True) is allowed
    # Operator-written cases keep their free spelling and order.
    assert case_headers_allowed(headers) is True


def test_model_headers_are_canonicalized_and_repeats_refused():
    assert list(canonical_model_headers({"x-requested-with": "XMLHttpRequest", "accept": "*/*"}).items()) == [
        ("Accept", "*/*"), ("X-Requested-With", "XMLHttpRequest")]
    with pytest.raises(ValueError, match="repeats a header name"):
        canonical_model_headers({"Accept": "*/*", "ACCEPT": "text/html"})
    # A name outside the vocabulary keeps its spelling, so the gate still sees and refuses it.
    assert case_headers_allowed(canonical_model_headers({"X-Tenant": "b"}), model_designed=True) is False


def test_model_request_sends_defaults_then_its_names_in_sorted_order():
    case = {"method": "GET", "path": "/orders", "designed_by": "model",
            "headers": {"Accept": "text/html", "If-None-Match": "*"}}
    _, _, headers, _, _ = _prepare_request({}, case)
    assert list(headers) == ["Accept-Encoding", "Connection", "Accept", "If-None-Match"]
    assert headers["Accept"] == "text/html"


def model_supervisor(monkeypatch, *, model_body=False, designed_by="model", headers=None):
    monkeypatch.setitem(sys.modules, "adapters", adapters)
    instance = Supervisor.__new__(Supervisor)
    entry = {"method": "POST", "path": "/chat", **({"model_body": True} if model_body else {})}
    instance.manifest = {"allowed_requests": [entry], "auth_profiles": []}
    case = {"id": "C1", "method": "POST", "path": "/chat", "identity": None,
            "headers": headers if headers is not None else {"Accept": "application/json"}, "body": {"q": "hi"}}
    if designed_by:
        case["designed_by"] = designed_by
    instance.spec = {"operation": "tool", "cases": [case]}
    instance.sessions = {}
    return instance


def chat_request(headers=None):
    return {"case_id": "C1", "method": "POST", "path": "/chat", "identity": None,
            "headers": headers or {"Accept": "application/json", "Content-Type": "application/json"},
            "body_b64": base64.b64encode(b'{"q":"hi"}').decode()}


def test_supervisor_sends_a_model_body_only_to_an_operator_marked_endpoint(monkeypatch):
    with pytest.raises(ValueError, match="model_body"):
        model_supervisor(monkeypatch).allowed_request(chat_request())
    case_id, _, method, path, headers, raw, _ = model_supervisor(monkeypatch, model_body=True).allowed_request(chat_request())
    assert (case_id, method, path, raw) == ("C1", "POST", "/chat", b'{"q":"hi"}')
    # The supervisor's own Content-Type joins the model's names in sorted order.
    assert list(headers)[-2:] == ["Accept", "Content-Type"]
    # An operator-written case is not a model body.
    model_supervisor(monkeypatch, designed_by=None).allowed_request(chat_request())


def test_supervisor_rechecks_the_model_vocabulary_before_tb_target(monkeypatch):
    # A sealed model step outside the vocabulary (as if the case gate had let it through) stops at the last trusted hop.
    tampered = {"Accept": "application/json", "X-Tenant": "tenant-b"}
    request = chat_request({**tampered, "Content-Type": "application/json"})
    with pytest.raises(AdapterBlocked):
        model_supervisor(monkeypatch, model_body=True, headers=tampered).allowed_request(request)
    # The same headers in an operator-written case are allowed.
    model_supervisor(monkeypatch, designed_by=None, headers=tampered).allowed_request(request)
