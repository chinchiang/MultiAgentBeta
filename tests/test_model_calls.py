"""Exercise complete answers and probes with controlled provider responses and timing."""
import asyncio
import copy
from types import SimpleNamespace

import pytest
from pydantic import BaseModel

from vibe_audit import providers
from vibe_audit.domain import RunInput, digest, new_run
from vibe_audit.model_calls import ModelAnswer, ModelCalls
from vibe_audit.policy import PolicyError


class Reply(BaseModel):
    ok: bool


@pytest.fixture
def context(monkeypatch):
    run = new_run("model-call-test", RunInput())
    profile = run["manifest"]["models"][0]
    profile.update(provider="openai_compatible", model_id="test", endpoint="http://127.0.0.1:11434/v1", max_output_tokens=256)
    saved = []
    cancelled = asyncio.Event()
    def check(run):
        if cancelled.is_set():
            raise asyncio.CancelledError()
    def event(run, message, level, agent_id):
        run["events"].append(dict(message=message, level=level, agent_id=agent_id))
    calls = ModelCalls(lambda run: saved.append(copy.deepcopy(run)), check, event, {run["id"]: asyncio.Lock()})
    monkeypatch.setattr(providers, "_load_litellm", lambda: SimpleNamespace())
    return run, profile, calls, saved, cancelled


def reply(content='{"ok":true}', *, finish="stop", usage=True):
    return {"choices": [{"finish_reason": finish, "message": {"content": content}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15} if usage else None}


async def test_schema_retry_settles_all_attempts_and_caches_an_isolated_answer(context, monkeypatch):
    run, profile, calls, saved, _ = context
    answers = iter([reply('{"wrong":true}'), reply()])
    async def invoke(*args):
        return next(answers)
    monkeypatch.setattr(providers, "_invoke", invoke)
    answer = await calls.answer(run, profile, "Review", {}, Reply, cache="review")
    assert answer == ModelAnswer({"ok": True}, profile["id"])
    assert run["usage"]["model_calls"] == 2 and run["usage"]["tokens"] == 30
    assert run["reserved_tokens"] == 0
    assert saved[0]["reserved_tokens"] > 0
    assert saved[-1]["model_outputs"]["review"]["data"] == {"ok": True}
    answer.data["ok"] = False
    assert (await calls.answer(run, profile, "Review", {}, Reply, cache="review")).data == {"ok": True}


async def test_budget_denial_during_retry_keeps_prior_usage_and_policy_reason(context, monkeypatch):
    run, profile, calls, saved, _ = context
    run["manifest"]["budget"]["max_model_calls"] = 1
    async def invoke(*args):
        return reply('{"wrong":true}')
    monkeypatch.setattr(providers, "_invoke", invoke)
    with pytest.raises(PolicyError, match="Model call budget exhausted"):
        await calls.answer(run, profile, "Review", {}, Reply)
    assert run["usage"]["tokens"] == 15 and run["usage"]["model_calls"] == 1
    assert saved[-1]["reserved_tokens"] == 0


async def test_unknown_usage_is_saved_and_prevents_another_dispatch(context, monkeypatch):
    run, profile, calls, saved, _ = context
    dispatches = []
    async def invoke(*args):
        dispatches.append(True)
        return reply(usage=False)
    monkeypatch.setattr(providers, "_invoke", invoke)
    with pytest.raises(providers.ProviderError, match="no verifiable usage"):
        await calls.answer(run, profile, "Review", {})
    assert saved[-1]["usage_unknown"] and saved[-1]["reserved_tokens"] > 0
    with pytest.raises(PolicyError, match="usage is unknown"):
        await calls.answer(run, profile, "Review", {})
    assert len(dispatches) == 1


async def test_parallel_calls_cannot_overreserve_and_cancel_settles_only_its_call(context, monkeypatch):
    run, profile, calls, saved, _ = context
    # Admit one reservation, but not two; an in-flight answer keeps the budget occupied.
    run["manifest"]["budget"]["max_tokens"] = 5000
    entered = asyncio.Event()
    released = asyncio.Event()
    async def invoke(*args):
        entered.set()
        await released.wait()
        return reply()
    monkeypatch.setattr(providers, "_invoke", invoke)
    first = asyncio.create_task(calls.answer(run, profile, "Review", {}))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        reserved = run["reserved_tokens"]
        assert reserved * 2 > 5000
        with pytest.raises(PolicyError, match="Insufficient token budget"):
            await calls.answer(run, profile, "Review", {})
        assert run["reserved_tokens"] == reserved and run["usage"]["model_calls"] == 1
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert run["usage"]["tokens"] == reserved and run["usage"]["tokens_estimated"]
        assert run["reserved_tokens"] == 0 and saved[-1]["reserved_tokens"] == 0
    finally:
        first.cancel()
        await asyncio.gather(first, return_exceptions=True)


async def test_cancelled_parallel_call_keeps_the_other_reservation(context, monkeypatch):
    run, profile, calls, _, _ = context
    entered = {key: asyncio.Event() for key in ("one", "two")}
    release = asyncio.Event()
    async def invoke(library, profile, endpoint, origin, credential, messages, *args):
        key = "one" if '"one"' in messages[1]["content"] else "two"
        entered[key].set()
        await release.wait()
        return reply()
    monkeypatch.setattr(providers, "_invoke", invoke)
    tasks = [asyncio.create_task(calls.answer(run, profile, "Review", {"key": key})) for key in entered]
    try:
        await asyncio.wait_for(asyncio.gather(*(event.wait() for event in entered.values())), 2)
        total = run["reserved_tokens"]
        tasks[0].cancel()
        with pytest.raises(asyncio.CancelledError):
            await tasks[0]
        assert 0 < run["reserved_tokens"] < total
        charged = run["usage"]["tokens"]
        assert charged + run["reserved_tokens"] == total
        release.set()
        await tasks[1]
        assert run["usage"]["tokens"] == charged + 15 and run["reserved_tokens"] == 0
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.parametrize("writer", [None, "fallback"])
async def test_historical_cache_recovers_author_without_dispatch(context, monkeypatch, writer):
    run, profile, calls, _, _ = context
    kept = {"binding": digest({"profile": profile["id"], "instruction": "Review", "payload": {}}), "data": {"ok": True}}
    if writer:
        kept["answered_by"] = [writer]
    run["model_outputs"] = {"old": kept}
    async def unexpected(*args):
        pytest.fail("Historical cache must not dispatch")
    monkeypatch.setattr(providers, "generate_json", unexpected)
    assert await calls.answer(run, profile, "Review", {}, cache="old") == ModelAnswer({"ok": True}, writer or profile["id"])
    assert run["usage"]["model_calls"] == 0


@pytest.mark.parametrize("cancel", [False, True])
async def test_probe_uses_the_same_unknown_usage_and_cancel_settlement(context, monkeypatch, cancel):
    run, profile, calls, saved, _ = context
    entered = asyncio.Event()
    async def invoke(*args):
        entered.set()
        if cancel:
            await asyncio.Event().wait()
        return reply(usage=False)
    monkeypatch.setattr(providers, "_invoke", invoke)
    task = asyncio.create_task(calls.probe(run, profile))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert saved[-1]["usage"]["tokens_estimated"] and saved[-1]["reserved_tokens"] == 0
        else:
            with pytest.raises(providers.ProviderError):
                await task
            assert saved[-1]["usage_unknown"] and saved[-1]["reserved_tokens"] > 0
        assert not run["model_probes"]
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_recovery_preserves_reservation_and_discard_drops_only_rejected_cache(context, monkeypatch):
    run, profile, calls, saved, _ = context
    run["reserved_tokens"] = 3000
    run["model_outputs"] = {"rejected": {"data": {}}, "other": {"data": {"ok": True}}}
    calls.recover(run)
    assert saved[-1]["usage_unknown"] and saved[-1]["reserved_tokens"] == 3000
    calls.discard(run, ("rejected",))
    assert saved[-1]["model_outputs"] == {"other": {"data": {"ok": True}}}
    async def unexpected(*args):
        pytest.fail("Recovery must block paid dispatch")
    monkeypatch.setattr(providers, "_invoke", unexpected)
    with pytest.raises(PolicyError, match="usage is unknown"):
        await calls.answer(run, profile, "Review", {})


@pytest.mark.parametrize("finish", ["refusal", "length"])
@pytest.mark.parametrize("fallback_fails", [False, True])
async def test_fallback_answer_settles_both_models_and_only_caches_success(context, monkeypatch, finish, fallback_fails):
    run, profile, calls, saved, _ = context
    fallback = {**profile, "id": "fallback", "role": "fallback", "fallback_for": [profile["id"]]}
    run["manifest"]["models"].append(fallback)
    dispatched = []

    async def invoke(library, selected, *args):
        dispatched.append(selected["id"])
        return reply(finish=finish if selected["id"] == profile["id"] or fallback_fails else "stop")

    monkeypatch.setattr(providers, "_invoke", invoke)
    if fallback_fails:
        with pytest.raises(providers.ProviderError, match="Its fallback fallback failed too"):
            await calls.answer(run, profile, "Review", {}, Reply, cache="review")
        assert "review" not in run["model_outputs"]
        assert not run["limitations"]
        assert len(run["events"]) == 1
    else:
        answer = await calls.answer(run, profile, "Review", {}, Reply, cache="review")
        assert answer == ModelAnswer({"ok": True}, "fallback")
        assert saved[-1]["model_outputs"]["review"]["answered_by"] == ["fallback"]
        assert await calls.answer(run, profile, "Review", {}, Reply, cache="review") == answer
        assert len(run["limitations"]) == 1 and len(run["events"]) == 2
    assert dispatched == [profile["id"], "fallback"]
    assert run["usage"]["model_calls"] == 2 and run["usage"]["tokens"] == 30
    assert saved[-1]["reserved_tokens"] == 0


async def test_changed_question_replaces_cache_and_cancellation_before_dispatch_costs_nothing(context, monkeypatch):
    run, profile, calls, saved, cancelled = context
    dispatched = []

    async def invoke(*args):
        dispatched.append(True)
        return reply()

    monkeypatch.setattr(providers, "_invoke", invoke)
    await calls.answer(run, profile, "Review", {"revision": 1}, Reply, cache="review")
    await calls.answer(run, profile, "Review", {"revision": 2}, Reply, cache="review")
    assert len(dispatched) == 2 and run["usage"]["tokens"] == 30
    before = copy.deepcopy(saved[-1])
    cancelled.set()
    with pytest.raises(asyncio.CancelledError):
        await calls.answer(run, profile, "Review", {"revision": 3}, Reply, cache="review")
    assert run == before and len(dispatched) == 2
