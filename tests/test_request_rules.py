"""The request rules module, tested through its interface: a case and its manifest in, a request plan or a refusal out."""
import copy

import pytest

from vibe_audit.request_rules import RequestRefused, match_request, own_step, plan_case, read_only


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
    # The same headers in another order or letter case are the same step.
    headed = {**reset, "headers": {"X-Fixture-Control": "on", "Accept": "*/*"}}
    again = {**reset, "headers": {"accept": "*/*", "x-fixture-control": "on"}}
    steps = plan_case(fixture_manifest(), fixture_case(), live=True, lifecycle=[headed, again])["steps"]
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


def sealed_with(steps, base=None):
    """A case sealed with a request plan whose engine steps are these."""
    value = base or fixture_case()
    value["request_plan"] = {"version": 1, "steps": [
        {"id": "case", "phase": "case", "source": "operator", "method": value["method"], "path": value["path"],
         "identity": value["identity"], "headers": {}, "body": None, "read_only": True, "body_permitted": True},
        *steps]}
    return value


def engine_step(**changes):
    step = {"id": "reset", "phase": "reset", "source": "engine", "method": "POST", "path": "/__fixture/reset", "identity": None,
            "headers": {"X-Fixture-Control": "local-synthetic-control"}, "body": None, "read_only": False, "body_permitted": True}
    step.update(changes)
    return step


def test_a_sealed_cases_lifecycle_is_read_from_its_request_plan():
    steps = plan_case(fixture_manifest(), sealed_with([engine_step()]), live=True)["steps"]
    assert [(s["id"], s["headers"]) for s in steps[2:]] == [("reset", {"X-Fixture-Control": "local-synthetic-control"})]
    # Its engine steps are held to the same rules, which allowed_requests could never show: it carries no headers.
    assert refusal(fixture_manifest(), sealed_with([engine_step(headers={"Forwarded": "for=x"})])) == ("headers", "reset")
    assert refusal(fixture_manifest(), sealed_with([engine_step(path="/__fixture/wipe")])) == ("scope", "reset")


def sealed_case():
    value = fixture_case()
    value["request_plan"] = plan_case(fixture_manifest(), value, live=True)
    return value


def test_a_request_is_matched_to_the_plan_step_with_its_method_path_and_identity():
    step = match_request(fixture_manifest(), sealed_case(), {"method": "get", "path": "/orders/a", "identity": "alice"})
    assert (step["id"], step["source"]) == ("control:own", "operator")
    assert match_request(fixture_manifest(), sealed_case(), {"method": "POST", "path": "/__fixture/reset", "identity": None})["id"] == "lifecycle:1"


def match_refusal(request, value=None, scope=None):
    with pytest.raises(RequestRefused) as refused:
        match_request(scope or fixture_manifest(), value or sealed_case(), request)
    return refused.value.rule


def test_a_request_must_use_the_identity_of_the_step_it_names_not_any_identity_the_case_uses():
    # alice reads /orders/a as the control; the engine's reset runs with no identity. Neither lends its identity to the other.
    assert match_refusal({"method": "POST", "path": "/__fixture/reset", "identity": "alice"}) == "identity"
    assert match_refusal({"method": "GET", "path": "/orders/a", "identity": None}) == "identity"


def test_a_request_outside_the_run_scope_is_refused_as_that_before_it_is_looked_for_in_the_plan():
    assert match_refusal({"method": "GET", "path": "/admin", "identity": "alice"}) == "scope"
    # In the run's scope but no step of this case.
    wider = fixture_manifest()
    wider["allowed_requests"].append({"method": "GET", "path": "/admin"})
    assert match_refusal({"method": "GET", "path": "/admin", "identity": "alice"}, scope=wider) == "step"


def test_a_case_sealed_before_request_plans_is_matched_against_the_plan_its_fields_give():
    legacy = fixture_case()
    assert "request_plan" not in legacy
    assert match_request(fixture_manifest(), legacy, {"method": "POST", "path": "/__fixture/reset", "identity": None})["source"] == "engine"
    assert match_request(fixture_manifest(), legacy, {"method": "POST", "path": "/agent", "identity": "alice"})["id"] == "case"
    # It passed the case gate when it was sealed; a rule tightened since does not stop it from being matched.
    legacy["preconditions"][0]["headers"] = {"Forwarded": "for=x"}
    assert match_request(fixture_manifest(), legacy, {"method": "GET", "path": "/orders/a", "identity": "alice"})["id"] == "control:own"
    assert "request_plan" not in legacy


def test_an_engine_cases_own_request_is_not_read_back_as_a_lifecycle_step():
    # A case neither the model wrote nor the operator listed is the engine's, its own request included.
    engine_case = {**case(id="C9"), "preconditions": []}
    engine_case["request_plan"] = plan_case(manifest(), engine_case, live=True)
    assert [(s["id"], s["source"]) for s in engine_case["request_plan"]["steps"]] == [("case", "engine")]
    assert [s["id"] for s in plan_case(manifest(), engine_case, live=True)["steps"]] == ["case"]


def test_a_sealed_cases_own_steps_are_never_read_back_as_lifecycle_steps():
    # Changed after sealing, the plan's old case and control steps no longer match the case: they still are not lifecycle.
    changed = sealed_case()
    changed["method"] = "GET"
    changed["preconditions"][0]["path"] = "/orders/b"
    ids = [s["id"] for s in plan_case(manifest(allowed_requests=[{"method": "GET", "path": "/agent"}, {"method": "GET", "path": "/orders/b"},
                                                                  {"method": "POST", "path": "/__fixture/reset"}]), changed, live=True)["steps"]]
    assert ids == ["control:own", "case", "lifecycle:1"]
    # A plan that lists no steps has no lifecycle to read.
    assert [s["id"] for s in plan_case(fixture_manifest(), {**fixture_case(), "request_plan": {"version": 1}}, live=True)["steps"]] == ["control:own", "case"]


def test_a_sealed_plan_is_matched_as_sealed_even_where_the_cases_fields_would_give_another():
    held = sealed_case()
    held["request_plan"]["steps"].append(engine_step(id="instrument", path="/agent"))
    assert match_request(fixture_manifest(), held, {"method": "POST", "path": "/agent", "identity": None})["id"] == "instrument"


def test_an_identity_refusal_names_the_step_the_request_named():
    with pytest.raises(RequestRefused) as refused:
        match_request(fixture_manifest(), sealed_case(), {"method": "GET", "path": "/orders/a", "identity": "bob"})
    assert (refused.value.rule, refused.value.step) == ("identity", "control:own")


def test_a_request_or_scope_entry_naming_no_method_is_a_get():
    scope = manifest(allowed_requests=[{"path": "/orders/a"}, {"method": "GET", "path": "/orders/b"}])
    assert match_request(scope, sealed_with([], case()), {"path": "/orders/b", "identity": "alice"})["id"] == "case"
    assert match_refusal({"path": "/orders/a", "identity": "alice"}, value=sealed_with([], case()), scope=scope) == "step"


def test_a_lifecycle_step_sending_a_controls_request_stays_the_engines_and_is_told_apart_by_its_headers():
    # The engine probes the same method, path and identity as the model's control, with its own control header.
    probe = {"id": "probe", "phase": "setup", "method": "GET", "path": "/orders/a", "identity": "alice",
             "headers": {"X-Fixture-Control": "local-synthetic-control"}}
    model = {**fixture_case(), "designed_by": "model", "body": None, "method": "GET", "path": "/orders/b"}
    scope = manifest(allowed_requests=[{"method": "GET", "path": "/orders/b"}, {"method": "GET", "path": "/orders/a"}])
    model["request_plan"] = plan_case(scope, model, live=True, lifecycle=[probe])
    assert [(s["id"], s["source"]) for s in model["request_plan"]["steps"]] == [("control:own", "model"), ("case", "model"), ("probe", "engine")]
    request = {"method": "GET", "path": "/orders/a", "identity": "alice"}
    assert match_request(scope, model, request, expect={"headers": {"x-fixture-control": "local-synthetic-control"}})["id"] == "probe"
    assert match_request(scope, model, request, expect={"headers": {}})["id"] == "control:own"
    # Headers that tell neither apart, or no expected step at all, take the stricter rule: the model's.
    assert match_request(scope, model, request, expect={"headers": {"Accept": "text/html"}})["source"] == "model"
    assert match_request(scope, model, request, expect={"headers": {"X-Other": "local-synthetic-control"}})["source"] == "model"
    assert match_request(scope, model, request)["source"] == "model"


def test_whether_a_case_writes_is_read_from_its_plans_own_step_or_else_by_who_wrote_it():
    post = case(method="POST", path="/chat", body={"q": "hi"})
    planned = {**post, "request_plan": {"version": 1, "steps": [{"id": "case", "phase": "case", "source": "engine", "read_only": False}]}}
    assert read_only(post) is True and read_only(planned) is False
    # A plan without the case's own step, or no plan, leaves it to who wrote the case: only an operator's POST reads.
    for plan in ({"version": 1, "steps": []}, {"version": 1}, None):
        assert read_only({**post, "request_plan": plan}) is True
        assert read_only({**post, "request_plan": plan, "designed_by": "model"}) is False


def test_a_cases_own_step_is_the_plans_step_for_its_own_request():
    sealed = sealed_case()
    assert own_step(sealed) == next(s for s in sealed["request_plan"]["steps"] if s["id"] == "case")
    for plan in ({"version": 1, "steps": [engine_step()]}, {"version": 1}, None):
        assert own_step({**fixture_case(), "request_plan": plan}) is None


def test_an_own_step_that_does_not_say_it_reads_is_a_write():
    post = case(method="POST", path="/chat", body={"q": "hi"})
    assert read_only({**post, "request_plan": {"version": 1, "steps": [{"id": "case", "phase": "case"}]}}) is False
    assert read_only({**post, "request_plan": {"version": 1, "steps": [{"id": "case", "phase": "case", "read_only": True}]}}) is True


RULE_DEFINITIONS = {
    # The vocabularies and rule functions themselves.
    "a header vocabulary or rule": r"^(_FORBIDDEN_HEADERS|RELAY_HEADERS|MODEL_CASE_HEADER_NAMES|MODEL_CASE_HEADERS|SAFE_METHODS|_MODEL_HEADER_VALUES)\s*=|"
                                   r"^def (state_changing|case_headers_allowed|model_header_vocabulary|canonical_model_headers|model_header_list_error|request_path_problem|model_body_denied)\b",
    # The body rule: only an endpoint the operator marked model_body takes a model's body or write.
    "the model_body rule": r"""get\(\s*["']model_body["']\s*\)\s*is\s+True""",
    # The run scope: the method and path pairs the operator allows.
    "the run scope": r"""for\s+r\s+in\s+[\w.\[\]"']*get\(\s*["']allowed_requests["']""",
}


def test_every_request_rule_is_defined_only_in_the_request_rules_module():
    import re
    from pathlib import Path
    backend = Path(__file__).resolve().parents[1] / "backend" / "vibe_audit"
    found = []
    for module in sorted(backend.glob("*.py")):
        if module.name == "request_rules.py":
            continue
        text = module.read_text(encoding="utf8")
        found += [f"{module.name}: {rule}" for rule, pattern in RULE_DEFINITIONS.items() if re.search(pattern, text, re.M)]
    assert found == []


def test_no_module_reads_a_request_rule_from_the_transport_module():
    # The transport reads the rules it applies from request_rules; it no longer passes them on.
    import re
    from pathlib import Path
    from vibe_audit import request_rules
    rules = {name for name in vars(request_rules) if not name.startswith("__")} - {"annotations", "re"}
    backend = Path(__file__).resolve().parents[1] / "backend" / "vibe_audit"
    found = []
    for module in sorted(backend.glob("*.py")):
        for names in re.findall(r"from \.?adapters import \(?([^)\n]*(?:\n[^)\n]*)*?)\)?\s*(?:#.*)?$", module.read_text(encoding="utf8"), re.M):
            found += [f"{module.name}: {name}" for name in re.findall(r"\w+", names) if name in rules]
    assert found == []


def test_with_the_manifest_a_case_sealed_before_request_plans_has_its_own_step_rebuilt():
    # A model POST to an endpoint the operator did not mark model_body: a write that may carry no body in a live run.
    scope = manifest(allowed_requests=[{"method": "POST", "path": "/chat"}])
    legacy = case(designed_by="model", method="POST", path="/chat", body={"q": "hi"}, identity=None, preconditions=[])
    assert own_step(legacy) is None
    step = own_step(legacy, scope)
    assert (step["id"], step["source"], step["read_only"], step["body_permitted"]) == ("case", "model", False, False)
    assert own_step(legacy, manifest(allowed_requests=[{"method": "POST", "path": "/chat", "model_body": True}]))["body_permitted"] is True
    # An unlisted case is the engine's, so its POST is a write; one the operator listed may declare it a read.
    unlisted = {**legacy, "id": "C9", "designed_by": None}
    assert (own_step(unlisted, scope)["source"], own_step(unlisted, scope)["read_only"]) == ("engine", False)
    assert own_step({**unlisted, "id": "C1"}, scope)["read_only"] is True
    # A sealed plan is read as sealed, the manifest notwithstanding; nothing is written back.
    assert own_step(sealed_case(), scope)["source"] == "operator"
    assert "request_plan" not in legacy
    # The case's own step, not the control the plan lists before it.
    assert own_step(case(), manifest())["id"] == "case"
