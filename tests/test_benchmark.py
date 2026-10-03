import json

import pytest

from vibe_audit.benchmark import ARMS, DEFAULT_DATASET, BenchmarkError, compute_metrics, load_dataset, run_benchmark, schedule, traditional_ast


def test_synthetic_experiment_has_paired_equal_caps_and_no_efficacy_claim(tmp_path):
    result = run_benchmark(output_dir=tmp_path, repetitions=2)
    assert len(result["records"]) == 2 * 2 * len(ARMS)
    assert result["status"] == "completed"
    assert result["efficacy_status"] == "not_established"
    assert all(row["metrics"] is None and row["preview_metrics"] is not None for row in result["records"])
    assert len({_budget_key(row["budget"]) for row in result["records"]}) == 1
    assert all(not row["efficacy_eligible"] for row in result["summary"]["paired_comparisons"])
    assert (tmp_path / "report.json").exists()
    independent = next(row for row in result["records"] if row["arm"] == "heterogeneous_independent")
    assert len({item["input_hash"] for item in independent["observations"]}) == 1
    debate = next(row for row in result["records"] if row["arm"] == "debate")
    assert debate["observations"][-1]["input_hash"] != debate["observations"][0]["input_hash"]


def _budget_key(budget):
    return json.dumps(budget, sort_keys=True)


def test_metrics_cover_common_miss_minority_and_unknown_adjudication():
    gold = {"positive_ids": ["one", "two", "missed"], "negative_ids": ["false"]}
    metrics = compute_metrics(["one", "false"], ["one"], [["one", "false"], ["two"], []], gold, True)
    assert metrics["precision"] == .5
    assert metrics["recall"] == pytest.approx(1 / 3)
    assert metrics["common_miss_rate"] == pytest.approx(1 / 3)
    assert metrics["minority_retention"] == .5
    assert metrics["reproduce_rate"] == 1
    unknown = compute_metrics(["new-unreviewed"], [], [], gold, False)
    assert unknown["precision"] is None
    assert unknown["unadjudicated_ids"] == ["new-unreviewed"]


def test_family_split_prevents_fork_leakage(tmp_path):
    dataset = load_dataset(DEFAULT_DATASET)
    dataset["projects"][-1]["family"] = dataset["projects"][0]["family"]
    path = tmp_path / "leak.json"
    path.write_text(json.dumps(dataset), encoding="utf-8")
    with pytest.raises(BenchmarkError, match="cannot cross"):
        load_dataset(path)


def test_real_gold_without_named_reviewers_or_evidence_is_rejected(tmp_path):
    data = load_dataset(DEFAULT_DATASET)
    gold = data["projects"][0]["samples"][0]["gold"]
    gold["human_reviewed"] = True
    path = tmp_path / "unreviewed.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(BenchmarkError, match="two independent"):
        load_dataset(path)
    gold.update(human_reviewed=False, oracle_evidence=[])
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(BenchmarkError, match="evidence"):
        load_dataset(path)


def test_budget_exhaustion_never_becomes_a_clean_completed_arm():
    report = run_benchmark(repetitions=1, budget={"max_tokens": 1, "max_requests": 1, "max_model_calls": 1, "max_seconds": 1})
    models = [row for row in report["records"] if row["arm"] != "traditional"]
    assert all(row["status"] == "blocked" for row in models)
    assert all(not row["finding_ids"] for row in models)
    assert report["status"] == "incomplete"


def test_local_tools_are_real_while_model_arms_remain_blocked():
    report = run_benchmark(mode="local_tools", repetitions=1)
    traditional = [row for row in report["records"] if row["arm"] == "traditional"]
    assert all(not row["simulated"] and row["status"] == "completed" for row in traditional)
    assert all(row["finding_ids"] == ["ast:eval:app.py:2"] for row in traditional)
    assert all(row["status"] == "blocked" for row in report["records"] if row["arm"] != "traditional")
    assert all(row["metrics"] is None for row in report["records"])


def test_static_baseline_does_not_execute_input(tmp_path):
    marker = tmp_path / "must-not-exist"
    payload = f"open({str(marker)!r}, 'w').write('unsafe')\neval(user_input)"
    result = traditional_ast({"files": [{"path": "app.py", "content": payload}]})
    assert result["finding_ids"] == ["ast:eval:app.py:2"]
    assert not marker.exists()


def test_schedule_randomization_is_reproducible_and_pair_complete():
    dataset = load_dataset(DEFAULT_DATASET)
    first = schedule(dataset, seed=12)
    assert first == schedule(dataset, seed=12)
    assert first != schedule(dataset, seed=13)
    for pair in {job["pair_id"] for job in first}:
        assert {job["arm"] for job in first if job["pair_id"] == pair} == set(ARMS)


def _profiles():
    return {alias: {"id": "reviewer-" + alias, "role": "reviewer", "provider": "openai_compatible", "model_id": "test-" + alias,
                    "family": "family-" + alias, "endpoint": "http://127.0.0.1:9999/v1", "credential_env": "", "temperature": 0, "max_output_tokens": 1000}
            for alias in "abc"}


def test_live_runner_executes_injected_strategies_with_equal_sealed_tool_context():
    calls, tool_calls = [], []
    async def tools(input_data, budget):
        tool_calls.append(input_data)
        return traditional_ast(input_data)
    async def models(profile, system, payload, policy):
        assert "gold" not in payload
        assert policy["max_tokens"] <= 12000
        assert "response_schema" in policy
        calls.append((profile, payload))
        return {"data": {"finding_ids": ["ast:eval:app.py:2"], "rationale": "Deterministic injected adapter test, not a real model result"},
                "usage": {"tokens": 100, "model_calls": 1}}
    report = run_benchmark(mode="live", repetitions=1, profiles=_profiles(), model_policy={"data_policy": "local_only", "allowed_model_origins": []},
                           model_runner=models, tool_runner=tools)
    assert len(tool_calls) == 2
    assert len(calls) == 26
    assert report["status"] == "completed"
    assert all(row["metrics"] is None for row in report["records"])
    for pair in {r["pair_id"] for r in report["records"]}:
        assert len({r["tool_context_hash"] for r in report["records"] if r["pair_id"] == pair}) == 1
    independent = next(r for r in report["records"] if r["arm"] == "heterogeneous_independent")
    assert len({o["input_hash"] for o in independent["observations"]}) == 1
    assert all(r["usage"]["tokens"] <= r["budget"]["max_tokens"] for r in report["records"])


def test_live_missing_profiles_block_without_dispatch():
    async def forbidden(*args):
        raise AssertionError("No profile means no model dispatch")
    report = run_benchmark(mode="live", repetitions=1, model_runner=forbidden)
    assert report["status"] == "incomplete"
    assert all(r["status"] == "blocked" for r in report["records"] if r["arm"] != "traditional")


def test_live_provider_unknown_usage_reserves_allocation_and_stops_arm():
    from vibe_audit.providers import ProviderError
    async def failed(*args):
        raise ProviderError("Unknown billing", code="usage_unavailable", usage={"tokens": 0, "model_calls": 1, "tokens_known": False})
    report = run_benchmark(mode="live", repetitions=1, profiles=_profiles(), model_policy={"data_policy": "local_only"}, model_runner=failed)
    single = next(r for r in report["records"] if r["arm"] == "single_a")
    assert single["usage"]["tokens"] == single["budget"]["max_tokens"]
    assert single["status"] == "blocked"


def test_live_every_model_step_gets_equal_retry_attempts():
    from vibe_audit.providers import MAX_ATTEMPTS
    allowances = []
    async def models(profile, system, payload, policy):
        allowances.append(policy["max_model_calls"])
        return {"data": {"finding_ids": [], "rationale": "Injected adapter"}, "usage": {"tokens": 10, "model_calls": 1}}
    run_benchmark(mode="live", repetitions=1, profiles=_profiles(), model_policy={"data_policy": "local_only"}, model_runner=models)
    assert len(allowances) == 26 and min(allowances) >= MAX_ATTEMPTS
    with pytest.raises(BenchmarkError, match="attempts"):
        run_benchmark(mode="live", repetitions=1, profiles=_profiles(), model_policy={"data_policy": "local_only"}, model_runner=models,
                      budget={"max_tokens": 12000, "max_seconds": 60, "max_requests": 12, "max_model_calls": 6})


def test_completion_counts_blocked_runs_and_paired_blocked_sides():
    from vibe_audit.benchmark import summarize
    scored = {"precision": 1.0, "recall": 1.0, "common_miss_rate": 0.0, "minority_retention": 1.0, "reproduce_rate": None, "completion": 1}
    usage = {"tokens": 0, "requests": 0, "model_calls": 0, "latency_seconds": 0}
    def record(arm, pair, status):
        done = status == "completed"
        return {"arm": arm, "pair_id": pair, "status": status, "metrics": None, "preview_metrics": scored if done else None,
                "usage": usage, "cost_usd": None}
    records = [record("single_a", "p1", "completed"), record("single_a", "p2", "completed"),
               record("single_b", "p1", "completed"), record("single_b", "p2", "blocked")]
    summary = summarize(records)
    # Half the single_b schedule never ran; that must lower completion, not disappear from it.
    assert summary["arms"]["single_b"]["completion"] == 0.5
    assert summary["arms"]["single_b"]["preview_metrics"]["completion"] == 0.5
    assert summary["arms"]["single_b"]["metrics"] is None
    deltas = {p["pair_id"]: p["paired_differences"] for p in summary["paired_comparisons"] if p["arm"] == "single_b"}
    assert deltas["p1"]["completion"] == 0 and deltas["p2"] == {"precision": None, "recall": None, "reproduce_rate": None, "completion": -1}


def test_unfinished_arm_does_not_enter_quality_averages():
    async def models(profile, system, payload, policy):
        if payload["peer_reviews"]:
            raise ValueError("Adjudicator returned an invalid contract")
        return {"data": {"finding_ids": ["ast:eval:app.py:2"], "rationale": "Injected adapter"}, "usage": {"tokens": 10, "model_calls": 1}}
    report = run_benchmark(mode="live", repetitions=1, profiles=_profiles(), model_policy={"data_policy": "local_only"}, model_runner=models)
    debate = [r for r in report["records"] if r["arm"] == "debate"]
    assert all(r["status"] == "incomplete" and r["preview_metrics"]["recall"] is not None for r in debate)
    summary = report["summary"]["arms"]["debate"]["preview_metrics"]
    assert summary["recall"] is None and summary["completion"] == 0
    assert report["summary"]["arms"]["single_a"]["preview_metrics"]["recall"] is not None
    paired = [p for p in report["summary"]["paired_comparisons"] if p["arm"] == "debate"]
    assert all(p["paired_differences"]["recall"] is None and p["paired_differences"]["completion"] == -1 for p in paired)
