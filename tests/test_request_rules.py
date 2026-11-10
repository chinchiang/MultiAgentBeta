"""The request rules module, tested through its interface: a case and its manifest in, a request plan or a refusal out."""
import copy

import pytest

from vibe_audit.request_rules import RequestRefused, plan_case


def manifest(**changes):
    value = {"allowed_requests": [{"method": "GET", "path": "/orders/b"}, {"method": "GET", "path": "/orders/a"}],
             "auth_profiles": [{"id": "alice", "model_selectable": True}, {"id": "admin"}],
             "cases": [{"id": "C1"}]}
    value.update(changes)
    return value


def case(**changes):
    value = {"id": "C1", "method": "GET", "path": "/orders/b", "identity": "alice", "headers": {}, "body": None,
             "side_effects": False,
             "preconditions": [{"name": "own", "method": "GET", "path": "/orders/a", "identity": "alice",
                                "expected_status": 200, "required_text": ["ORDER-A"]}]}
    value.update(changes)
    return value


def test_an_operator_case_is_planned_as_its_controls_then_its_own_request():
    plan = plan_case(manifest(), case(), live=True)
    assert plan == {"version": 1, "steps": [
        {"id": "control:own", "phase": "control", "source": "operator", "method": "GET", "path": "/orders/a",
         "identity": "alice", "headers": {}, "body": None, "read_only": True, "body_permitted": True},
        {"id": "case", "phase": "case", "source": "operator", "method": "GET", "path": "/orders/b",
         "identity": "alice", "headers": {}, "body": None, "read_only": True, "body_permitted": True}]}


def refusal(manifest_value, case_value, *, live=True, lifecycle=None):
    with pytest.raises(RequestRefused) as refused:
        plan_case(manifest_value, case_value, live=live, lifecycle=lifecycle)
    return refused.value.rule, refused.value.step


def test_a_header_no_request_may_carry_refuses_the_plan_and_names_its_step():
    controlled = case()
    controlled["preconditions"][0]["headers"] = {"X-HTTP-Method-Override": "DELETE"}
    assert refusal(manifest(), controlled) == ("headers", "control:own")


def test_a_model_header_the_operator_did_not_list_for_its_endpoint_refuses_the_plan():
    listed = manifest(allowed_requests=[{"method": "GET", "path": "/orders/b", "model_headers": {"Accept": ["application/json"]}},
                                        {"method": "GET", "path": "/orders/a"}])
    designed = case(designed_by="model", headers={"Accept": "text/html"})
    assert refusal(listed, designed) == ("headers", "case")
    # The listed value is one the model may send.
    assert plan_case(listed, case(designed_by="model", headers={"Accept": "application/json"}), live=True)["steps"][1]["headers"] == {"Accept": "application/json"}


@pytest.mark.parametrize("headers", [[], "", 0])
def test_headers_that_are_not_a_mapping_refuse_the_plan_even_when_empty(headers):
    controlled = case()
    controlled["preconditions"][0]["headers"] = headers
    assert refusal(manifest(), controlled) == ("headers", "control:own")


def test_a_model_case_may_use_only_identities_the_operator_marked_model_selectable():
    controlled = case(designed_by="model")
    controlled["preconditions"][0]["identity"] = "admin"
    assert refusal(manifest(), controlled) == ("identity", "control:own")
    assert refusal(manifest(), case(designed_by="model", identity="admin")) == ("identity", "case")
    # An operator writes its own cases with any of its test identities.
    assert plan_case(manifest(), case(identity="admin"), live=True)["steps"][1]["identity"] == "admin"


def test_a_live_plan_holds_every_step_to_the_operators_scope():
    assert refusal(manifest(), case(path="/admin")) == ("scope", "case")
    controlled = case()
    controlled["preconditions"][0]["path"] = "/admin"
    assert refusal(manifest(), controlled) == ("scope", "control:own")
    # A demo plan sends nothing to a target, so it has no scope to keep.
    assert plan_case(manifest(), case(path="/admin"), live=False)["steps"][1]["path"] == "/admin"


def test_rules_are_checked_one_rule_at_a_time_header_then_identity_then_scope():
    # The first rule broken anywhere decides the refusal, as the case gate has always reported it.
    out_of_scope_admin = case(designed_by="model", path="/admin", identity="admin", headers={"Forwarded": "for=x"})
    assert refusal(manifest(), out_of_scope_admin)[0] == "headers"
    assert refusal(manifest(), {**out_of_scope_admin, "headers": {}})[0] == "identity"
    assert refusal(manifest(), {**out_of_scope_admin, "headers": {}, "identity": "alice"})[0] == "scope"


def fixture_case():
    """A case as the engine seals a fixture case today: its lifecycle in allowed_requests, its own requests repeated there."""
    value = case(path="/agent", method="POST", body={"q": "hi"})
    value["allowed_requests"] = [{"method": "POST", "path": "/agent", "identity": "alice"},
                                 {"method": "GET", "path": "/orders/a", "identity": "alice"},
                                 {"method": "POST", "path": "/__fixture/reset", "identity": None}]
    return value


def fixture_manifest():
    return manifest(allowed_requests=[{"method": "POST", "path": "/agent"}, {"method": "GET", "path": "/orders/a"},
                                      {"method": "POST", "path": "/__fixture/reset"}])


def test_a_fixture_cases_lifecycle_follows_its_own_request_as_engine_steps():
    steps = plan_case(fixture_manifest(), fixture_case(), live=True)["steps"]
    assert [(s["id"], s["phase"], s["source"], s["method"], s["path"], s["read_only"]) for s in steps] == [
        ("control:own", "control", "operator", "GET", "/orders/a", True),
        ("case", "case", "operator", "POST", "/agent", True),
        ("lifecycle:1", "lifecycle", "engine", "POST", "/__fixture/reset", False)]


def test_a_lifecycle_step_is_held_to_the_header_and_scope_rules_too():
    reset = {"id": "reset", "phase": "reset", "method": "POST", "path": "/__fixture/reset", "identity": None,
             "headers": {"X-HTTP-Method-Override": "DELETE"}, "body": {}}
    assert refusal(fixture_manifest(), fixture_case(), lifecycle=[reset]) == ("headers", "reset")
    outside = {**reset, "headers": {}, "path": "/__fixture/wipe"}
    assert refusal(fixture_manifest(), fixture_case(), lifecycle=[outside]) == ("scope", "reset")
    # Passed in, the lifecycle replaces the one the case carries.
    steps = plan_case(fixture_manifest(), fixture_case(), live=True, lifecycle=[{**reset, "headers": {}}])["steps"]
    assert [(s["id"], s["phase"], s["body"]) for s in steps[2:]] == [("reset", "reset", {})]


def body_permitted(manifest_value, case_value, *, live=True):
    return plan_case(manifest_value, case_value, live=live)["steps"][-1]["body_permitted"]


def test_a_model_write_may_carry_a_body_only_to_an_endpoint_the_operator_marked_model_body():
    scope = [{"method": "POST", "path": "/chat"}, {"method": "GET", "path": "/orders/a"}]
    write = case(designed_by="model", method="POST", path="/chat", body={"q": "hi"})
    assert body_permitted(manifest(allowed_requests=scope), write) is False
    # A model POST without a body is still a write.
    assert body_permitted(manifest(allowed_requests=scope), {**write, "body": None}) is False
    marked = [{**scope[0], "model_body": True}, scope[1]]
    assert body_permitted(manifest(allowed_requests=marked), write) is True
    # A model read without a body, an operator's own write and a demo plan carry no model-chosen payload anywhere.
    assert body_permitted(manifest(allowed_requests=[{"method": "GET", "path": "/orders/b"}, scope[1]]), case(designed_by="model")) is True
    assert body_permitted(manifest(allowed_requests=scope), {**write, "designed_by": None}) is True
    assert body_permitted(manifest(allowed_requests=scope), write, live=False) is True


def test_only_a_case_from_the_operators_own_list_is_the_operators_and_may_declare_a_post_read_only():
    post = case(method="POST", path="/chat", body={"q": "hi"})
    scope = manifest(allowed_requests=[{"method": "POST", "path": "/chat"}, {"method": "GET", "path": "/orders/a"}])
    assert [(s["source"], s["read_only"]) for s in plan_case(scope, post, live=True)["steps"]] == [("operator", True), ("operator", True)]
    # A case neither the model wrote nor the operator listed is the engine's, and its POST is a write.
    unlisted = {**post, "id": "C9"}
    assert [(s["source"], s["read_only"]) for s in plan_case(scope, unlisted, live=True)["steps"]] == [("engine", True), ("engine", False)]
    assert [s["source"] for s in plan_case(scope, {**post, "designed_by": "model"}, live=True)["steps"]] == ["model", "model"]


def test_a_plan_is_plain_data_that_survives_a_json_round_trip():
    import json
    plan = plan_case(fixture_manifest(), fixture_case(), live=True)
    assert json.loads(json.dumps(plan)) == plan
    # Planning reads the case and the manifest and changes neither.
    sealed, scope = fixture_case(), fixture_manifest()
    before = copy.deepcopy((sealed, scope))
    plan_case(scope, sealed, live=True)
    assert (sealed, scope) == before


def test_a_request_the_case_declares_side_effects_for_is_never_read_only():
    steps = plan_case(manifest(), case(side_effects=True), live=True)["steps"]
    assert [(s["id"], s["read_only"]) for s in steps] == [("control:own", True), ("case", False)]


def test_a_lifecycle_step_listed_twice_is_planned_once():
    reset = {"method": "POST", "path": "/__fixture/reset", "identity": None}
    steps = plan_case(fixture_manifest(), fixture_case(), live=True, lifecycle=[reset, dict(reset)])["steps"]
    assert [s["id"] for s in steps] == ["control:own", "case", "lifecycle:1"]


def test_a_scope_entry_naming_no_method_marks_a_get_for_model_bodies():
    scope = [{"path": "/orders/b", "model_body": True}, {"method": "GET", "path": "/orders/a"}, {"method": "GET", "path": "/orders/b"}]
    assert body_permitted(manifest(allowed_requests=scope), case(designed_by="model", body={"q": "hi"})) is True


def test_a_refusal_reads_as_the_rule_it_names():
    controlled = case()
    controlled["preconditions"][0]["headers"] = {"Forwarded": "for=x"}
    with pytest.raises(RequestRefused) as refused:
        plan_case(manifest(), controlled, live=True)
    assert str(refused.value) == "headers"
