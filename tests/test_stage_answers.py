"""StageAnswers: who answers a stage's role, and whether its answer is kept, tested through its interface with a fake port."""
import asyncio

import pytest
from pydantic import BaseModel, ConfigDict

from fakes import FakePort, answer_with, asked, reply
from vibe_audit.answers import ModelAnswers
from vibe_audit.domain import RunInput, digest, new_run
from vibe_audit.policy import PolicyError
from vibe_audit.providers import ProviderError
from vibe_audit.stage_answers import StageAnswers
from vibe_audit.store import Store


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path)
    yield value
    value.close()


@pytest.fixture
def run(store):
    value = new_run("run-1", RunInput(name="Stage answers"))
    store.save(value)
    return value


def stage(run, store, port=None, check_active=lambda: None):
    answers = ModelAnswers(run, store=store, port=port or FakePort(), lock=asyncio.Lock(), check_active=check_active)
    return StageAnswers(run, answers)


def add_agent(run, role, agent_id=None):
    commander = next(p for p in run["manifest"]["models"] if p["role"] == "commander")
    agent = {**commander, "id": agent_id or role, "role": role, "model_id": f"{role}-model", "family": f"{role}-family"}
    run["manifest"]["models"].append(agent)
    return agent


def test_a_role_with_no_dedicated_agent_is_answered_by_the_commander_and_one_with_its_own_agent_by_that_agent(run, store):
    assert stage(run, store).seat("threat_modeler").agent["id"] == "commander"
    modeler = add_agent(run, "threat_modeler")
    assert stage(run, store).seat("threat_modeler").agent == modeler


def test_an_optional_role_with_no_agent_has_no_seat_rather_than_the_commanders(run, store):
    port = FakePort([])
    assert stage(run, store, port).seat("reporter") is None
    assert port.calls == []
    reporter = add_agent(run, "reporter")
    assert stage(run, store).seat("reporter").agent == reporter


def test_each_reviewer_has_a_seat_of_its_own_in_manifest_order(run, store):
    seats = stage(run, store).seats("reviewer")
    assert [s.agent["id"] for s in seats] == ["reviewer-a", "reviewer-b", "reviewer-c"]
    assert {s.role for s in seats} == {"reviewer"}


class Findings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ids: list[str]


async def test_an_answer_whose_checks_pass_is_kept_for_a_resumed_stage_as_the_model_gave_it(run, store):
    port = FakePort([answer_with({"ids": ["F-1"]})])
    async with stage(run, store, port).answer("threat_modeler", "Model", {"source": "x"}, Findings) as answer:
        assert answer.data == {"ids": ["F-1"]}
        # A check may rewrite what it was given; the kept answer is the model's own.
        answer.data["ids"].append("rewritten")
    kept = {"binding": digest({"profile": "commander", "instruction": "Model", "payload": {"source": "x"}}), "data": {"ids": ["F-1"]}, "answered_by": []}
    assert run["model_outputs"]["threat_modeler"] == kept
    assert store.get(run["id"])["model_outputs"]["threat_modeler"] == kept
    assert asked(port.calls[0]["messages"])[1] == {"source": "x"}


async def test_an_answer_whose_checks_fail_is_not_kept_and_the_failure_reaches_the_stage(run, store):
    port = FakePort([answer_with({"ids": ["F-1"]})])
    with pytest.raises(PolicyError, match="^Gate refused$"):
        async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings):
            raise PolicyError("Gate refused")
    assert "threat_modeler" not in run.get("model_outputs", {})
    assert "threat_modeler" not in store.get(run["id"]).get("model_outputs", {})


async def test_a_resumed_stage_asking_the_same_question_reuses_the_kept_answer_unsent_and_checks_it_again(run, store):
    port = FakePort([answer_with({"ids": ["F-1"]})])
    async with stage(run, store, port).answer("threat_modeler", "Model", {"source": "x"}, Findings):
        pass
    checked = []
    async with stage(run, store, port).answer("threat_modeler", "Model", {"source": "x"}, Findings) as answer:
        checked.append(answer.data)
    assert checked == [{"ids": ["F-1"]}]
    assert len(port.calls) == 1


async def test_a_reused_answer_that_fails_its_checks_is_dropped_so_the_next_resume_asks_again(run, store):
    port = FakePort([answer_with({"ids": ["F-1"]}), answer_with({"ids": ["F-2"]})])
    async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings):
        pass
    with pytest.raises(PolicyError):
        async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings):
            raise PolicyError("Gate refused")
    assert "threat_modeler" not in store.get(run["id"])["model_outputs"]
    async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings) as answer:
        assert answer.data == {"ids": ["F-2"]}
    assert len(port.calls) == 2


async def test_a_changed_question_is_asked_again(run, store):
    port = FakePort([answer_with({"ids": ["F-1"]}), answer_with({"ids": ["F-2"]})])
    async with stage(run, store, port).answer("threat_modeler", "Model", {"source": "old"}, Findings):
        pass
    async with stage(run, store, port).answer("threat_modeler", "Model", {"source": "new"}, Findings) as answer:
        assert answer.data == {"ids": ["F-2"]}
    assert len(port.calls) == 2


async def test_an_answer_kept_before_stage_answers_existed_is_reused_by_a_resumed_stage(run, store):
    # The record an earlier engine wrote: the model's answer and the fallback that gave it, bound to the question.
    run["model_outputs"] = {"threat_modeler": {"binding": digest({"profile": "commander", "instruction": "Model", "payload": {"source": "x"}}),
                                               "data": {"ids": ["F-1"]}, "answered_by": ["local"]}}
    port = FakePort([])
    async with stage(run, store, port).answer("threat_modeler", "Model", {"source": "x"}, Findings) as answer:
        assert (answer.data, answer.answered_by) == ({"ids": ["F-1"]}, "local")
    assert port.calls == []


async def test_a_reused_answer_costs_nothing(run, store):
    port = FakePort([answer_with({"ids": ["F-1"]}, tokens=15)])
    async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings):
        pass
    usage = dict(run["usage"])
    async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings):
        pass
    assert run["usage"] == usage
    assert run.get("reserved_tokens", 0) == 0


async def test_a_reused_answer_is_the_stages_own_copy(run, store):
    port = FakePort([answer_with({"ids": ["F-1"]})])
    async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings):
        pass
    async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings) as answer:
        answer.data["ids"].append("rewritten")
    async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings) as answer:
        assert answer.data == {"ids": ["F-1"]}


async def test_an_answer_that_breaks_the_contract_every_time_keeps_nothing(run, store):
    port = FakePort([reply('{"ids":"not a list"}'), reply('{"ids":"not a list"}')])
    with pytest.raises(ProviderError):
        async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings):
            raise AssertionError("A stage must not check an answer that broke its contract")
    assert "threat_modeler" not in run.get("model_outputs", {})


async def test_a_refused_answer_is_given_by_the_answering_agents_fallback_and_says_so_when_reused(run, store):
    commander = run["manifest"]["models"][0]
    run["manifest"]["models"].append({**commander, "id": "local", "role": "fallback", "model_id": "local-model", "family": "local", "fallback_for": ["commander"]})
    refused = ProviderError("Model refused the request", code="refusal", usage={"model_calls": 1, "tokens": 7, "tokens_known": True})
    port = FakePort([refused, answer_with({"ids": ["F-1"]})])
    # The commander stands in for the threat modeler, so the commander's fallback answers.
    async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings) as answer:
        assert answer.answered_by == "local"
    assert run["model_outputs"]["threat_modeler"]["answered_by"] == ["local"]
    async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings) as answer:
        assert answer.answered_by == "local"
    async with stage(run, store, FakePort([answer_with({"ids": []})])).answer("challenger", "Challenge", {}, Findings) as answer:
        assert answer.answered_by == "commander"


async def test_an_answer_is_held_to_the_stages_contract(run, store):
    port = FakePort([reply('{"ids":"not a list"}'), answer_with({"ids": ["F-1"]})])
    async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings) as answer:
        assert answer.data == {"ids": ["F-1"]}
    assert len(port.calls) == 2


async def test_a_reviewers_seat_is_answered_by_that_reviewer_and_its_answer_is_never_kept(run, store):
    port = FakePort([answer_with({"ids": []}), answer_with({"ids": []})])
    second = stage(run, store, port).seats("reviewer")[1]
    for _ in range(2):
        async with stage(run, store, port).answer(second, "Review", {}, Findings) as answer:
            assert answer.answered_by == "reviewer-b"
    # Reviews are sealed per reviewer in the run's reviews; asking again asks again.
    assert [call["agent_id"] for call in port.calls] == ["reviewer-b", "reviewer-b"]
    assert run.get("model_outputs", {}) == {}


async def test_a_new_answer_that_fails_its_checks_leaves_no_earlier_answer_kept_under_its_name(run, store):
    port = FakePort([answer_with({"ids": ["F-1"]}), answer_with({"ids": ["F-2"]})])
    async with stage(run, store, port).answer("threat_modeler", "Model", {"source": "old"}, Findings):
        pass
    with pytest.raises(PolicyError):
        async with stage(run, store, port).answer("threat_modeler", "Model", {"source": "new"}, Findings):
            raise PolicyError("Gate refused")
    assert "threat_modeler" not in store.get(run["id"])["model_outputs"]


async def test_a_reused_answer_is_not_given_to_a_run_that_has_stopped(run, store):
    port = FakePort([answer_with({"ids": ["F-1"]})])
    async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings):
        pass
    def stopped():
        raise asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        async with stage(run, store, port, check_active=stopped).answer("threat_modeler", "Model", {}, Findings):
            raise AssertionError("A stopped run's stage must not check an answer")


async def test_a_cancellation_during_the_checks_is_no_verdict_on_a_reused_answer(run, store):
    port = FakePort([answer_with({"ids": ["F-1"]})])
    async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings):
        pass
    with pytest.raises(asyncio.CancelledError):
        async with stage(run, store, port).answer("threat_modeler", "Model", {}, Findings):
            raise asyncio.CancelledError()
    assert store.get(run["id"])["model_outputs"]["threat_modeler"]["data"] == {"ids": ["F-1"]}


async def test_the_commanders_plan_and_the_reporters_order_are_kept_under_names_of_their_own(run, store):
    add_agent(run, "reporter")
    port = FakePort([answer_with({"ids": ["F-1"]}), answer_with({"ids": ["F-2"]})])
    async with stage(run, store, port).answer("commander", "Plan", {}, Findings):
        pass
    async with stage(run, store, port).answer("reporter", "Order", {}, Findings):
        pass
    kept = store.get(run["id"])["model_outputs"]
    assert {name: entry["data"] for name, entry in kept.items()} == {"commander_plan": {"ids": ["F-1"]}, "report_order": {"ids": ["F-2"]}}
