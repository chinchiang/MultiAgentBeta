import json

import pytest

from vibe_audit.benchmark import DEFAULT_DATASET, BenchmarkError, load_dataset, run_benchmark
from vibe_audit.benchmark_matching import _digest, apply_adjudications, build_report, build_worksheet


def _observation(findings, reproduced=()):
    return {"finding_ids": findings, "reproduced_ids": list(reproduced), "status": "completed",
            "tokens": 0, "requests": 0, "model_calls": 0, "latency_seconds": 0.0, "cost_usd": 0.0}


def _mini_dataset():
    """Two synthetic test-split samples whose fixtures report findings outside gold (unknowns to adjudicate)."""
    def sample(sid):
        return {"id": sid, "input": {"files": [{"path": "app.py", "content": "eval(user_input)\n"}]},
                "gold": {"positive_ids": [f"{sid}:pos"], "negative_ids": [f"{sid}:neg"], "human_reviewed": False,
                         "reviewers": [], "oracle_verified": True, "oracle_evidence": [f"fixture:{sid}"], "synthetic": True},
                "responses": {"traditional": [_observation([f"{sid}:pos"], [f"{sid}:pos"])],
                              "a": [_observation([f"{sid}:pos", f"{sid}:unknown-1", f"{sid}:unknown-2"])],
                              "b": [_observation([f"{sid}:pos", f"{sid}:unknown-1", f"{sid}:neg"])],
                              "c": [_observation([f"{sid}:pos"])],
                              "debate": [_observation([f"{sid}:pos", f"{sid}:unknown-1"])]}}
    return {"id": "matching-fixture", "version": "1", "synthetic": True, "description": "Blind-review matching test fixture",
            "projects": [{"id": "proj", "family": "fam", "split": "test", "samples": [sample("alpha"), sample("beta")]}]}


def _run(tmp_path, dataset):
    path = tmp_path / "dataset.json"
    path.write_text(json.dumps(dataset, ensure_ascii=False), encoding="utf-8")
    report = run_benchmark(dataset_path=path, output_dir=tmp_path, repetitions=1)
    records = [json.loads(line) for line in (tmp_path / "results.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    return dataset, records, report


def _adjudication(tmp_path, name, worksheet, decisions):
    path = tmp_path / f"adjudication-{name}.json"
    path.write_text(json.dumps({"schema_version": 1, "reviewer": name, "worksheet_hash": _digest(worksheet),
                                "decisions": decisions}, ensure_ascii=False), encoding="utf-8")
    return path


def _all_decisions(worksheet, verdict):
    return [{"sample_id": entry["sample_id"], "finding_id": finding["finding_id"], "verdict": verdict}
            for entry in worksheet["samples"] for finding in entry["unknown_findings"]]


def _mini_with_worksheet(tmp_path):
    dataset, records, report = _run(tmp_path, _mini_dataset())
    worksheet = build_worksheet(dataset, records)
    unknowns = sum(len(entry["unknown_findings"]) for entry in worksheet["samples"])
    assert unknowns == 4, "each fixture sample must report exactly two findings outside gold"
    return dataset, records, report, worksheet


def test_worksheet_is_blinded_and_complete(tmp_path):
    dataset, records, report, worksheet = _mini_with_worksheet(tmp_path)
    text = json.dumps(worksheet)
    for leak in ["arm", "single_a", "single_b", "single_c", "debate", "model_alias", "pair_id", "repetition",
                 "profile", "input_hash", "sealed_output_hash", "same_model_repeat", "heterogeneous_independent"]:
        assert leak not in text
    unknowns = {(entry["sample_id"], finding["finding_id"]) for entry in worksheet["samples"] for finding in entry["unknown_findings"]}
    for record in records:
        gold = next(s["gold"] for p in dataset["projects"] for s in p["samples"] if s["id"] == record["sample_id"])
        for finding_id in record["finding_ids"]:
            if finding_id not in set(gold["positive_ids"]) | set(gold["negative_ids"]):
                assert (record["sample_id"], finding_id) in unknowns
    assert worksheet["results_hash"] == _digest(records)


def test_bundled_dataset_worksheet_round_trips_idempotently(tmp_path):
    dataset, records, report = _run(tmp_path, load_dataset(DEFAULT_DATASET))
    worksheet = build_worksheet(dataset, records)
    assert worksheet["dataset_id"] == dataset["id"]
    alice = _adjudication(tmp_path, "alice", worksheet, _all_decisions(worksheet, "new_positive"))
    bob = _adjudication(tmp_path, "bob", worksheet, _all_decisions(worksheet, "new_positive"))
    updated, updated_records, record = apply_adjudications(dataset, records, [alice, bob])
    assert record["counts"]["decisions"] == sum(len(s["unknown_findings"]) for s in worksheet["samples"])
    for original, recomputed in zip(records, updated_records):
        assert recomputed["preview_metrics"] == original["preview_metrics"], "no unknowns means no metric change"


def test_agreement_backfills_gold_and_precision_becomes_computable(tmp_path):
    dataset, records, report, worksheet = _mini_with_worksheet(tmp_path)
    updated, updated_records, record = apply_adjudications(
        dataset, records, [_adjudication(tmp_path, "alice", worksheet, _all_decisions(worksheet, "new_positive")),
                           _adjudication(tmp_path, "bob", worksheet, _all_decisions(worksheet, "new_positive"))])
    for entry in worksheet["samples"]:
        gold = next(s["gold"] for p in updated["projects"] for s in p["samples"] if s["id"] == entry["sample_id"])
        for finding in entry["unknown_findings"]:
            assert finding["finding_id"] in gold["positive_ids"]
        assert gold["human_reviewed"] and {"alice", "bob"} <= set(gold["reviewers"])
    assert all(row["metrics"] is None for row in updated_records), "synthetic gold can never become efficacy-eligible"
    scored = [row for row in updated_records if row["preview_metrics"]]
    assert scored and all(row["preview_metrics"]["precision"] is not None and not row["preview_metrics"]["unadjudicated_ids"] for row in scored)
    assert record["counts"]["agreed"] == record["counts"]["decisions"] and record["counts"]["arbitrated"] == 0
    assert "cannot prove" in record["declaration"]
    rebuilt = build_report(report, updated, updated_records, record)
    assert rebuilt["efficacy_status"] == "not_established"
    assert rebuilt["adjudication"]["reviewers"] == ["alice", "bob"]
    assert any("adjudication" in line for line in rebuilt["limitations"])
    singles = [row["preview_metrics"]["precision"] for row in updated_records
               if row["arm"] == "single_a" and row["status"] == "completed" and row["preview_metrics"]]
    assert rebuilt["summary"]["arms"]["single_a"]["preview_metrics"]["precision"] == pytest.approx(sum(singles) / len(singles))


def test_not_a_vulnerability_backfills_negatives(tmp_path):
    dataset, records, report, worksheet = _mini_with_worksheet(tmp_path)
    updated, updated_records, _ = apply_adjudications(
        dataset, records, [_adjudication(tmp_path, "alice", worksheet, _all_decisions(worksheet, "not_a_vulnerability")),
                           _adjudication(tmp_path, "bob", worksheet, _all_decisions(worksheet, "not_a_vulnerability"))])
    for entry in worksheet["samples"]:
        gold = next(s["gold"] for p in updated["projects"] for s in p["samples"] if s["id"] == entry["sample_id"])
        for finding in entry["unknown_findings"]:
            assert finding["finding_id"] in gold["negative_ids"]
    assert all(row["preview_metrics"]["precision"] is not None for row in updated_records if row["preview_metrics"])
    assert all(not row["preview_metrics"]["unadjudicated_ids"] for row in updated_records if row["preview_metrics"])


def test_disagreement_blocks_and_arbiter_resolves(tmp_path):
    dataset, records, report, worksheet = _mini_with_worksheet(tmp_path)
    first = _all_decisions(worksheet, "new_positive")
    second = [dict(decision, verdict="not_a_vulnerability" if index == 0 else decision["verdict"])
              for index, decision in enumerate(first)]
    disputed = (second[0]["sample_id"], second[0]["finding_id"])
    with pytest.raises(BenchmarkError, match="Unresolved disagreements"):
        apply_adjudications(dataset, records, [_adjudication(tmp_path, "alice", worksheet, first),
                                               _adjudication(tmp_path, "bob", worksheet, second)])
    arbiter = _adjudication(tmp_path, "carol", worksheet, [first[0] | {"verdict": "not_a_vulnerability"}])
    updated, updated_records, record = apply_adjudications(dataset, records, [_adjudication(tmp_path, "alice", worksheet, first),
                                                                              _adjudication(tmp_path, "bob", worksheet, second)], [arbiter])
    assert record["counts"]["arbitrated"] == 1
    entry = next(a for a in record["decisions"] if (a["sample_id"], a["finding_id"]) == disputed)
    assert entry["arbiter"] == "carol" and entry["verdict"] == "not_a_vulnerability"
    gold = next(s["gold"] for p in updated["projects"] for s in p["samples"] if s["id"] == disputed[0])
    assert disputed[1] in gold["negative_ids"]
    assert "carol" in gold["reviewers"]


def test_incomplete_or_foreign_decisions_are_rejected(tmp_path):
    dataset, records, report, worksheet = _mini_with_worksheet(tmp_path)
    full = _all_decisions(worksheet, "new_positive")
    assert len(full) >= 2
    with pytest.raises(BenchmarkError, match="incomplete"):
        apply_adjudications(dataset, records, [_adjudication(tmp_path, "alice", worksheet, full[:-1]),
                                               _adjudication(tmp_path, "bob", worksheet, full)])
    foreign = full[1:] + [{"sample_id": "no-such-sample", "finding_id": "no-such-finding", "verdict": "new_positive"}]
    with pytest.raises(BenchmarkError, match="not an unadjudicated finding"):
        apply_adjudications(dataset, records, [_adjudication(tmp_path, "alice", worksheet, foreign),
                                               _adjudication(tmp_path, "bob", worksheet, full)])
    with pytest.raises(BenchmarkError, match="Duplicate decision"):
        apply_adjudications(dataset, records, [_adjudication(tmp_path, "alice", worksheet, full + [full[0]]),
                                               _adjudication(tmp_path, "bob", worksheet, full)])
    stale = json.loads(_adjudication(tmp_path, "alice", worksheet, full).read_text(encoding="utf-8"))
    stale["worksheet_hash"] = "0" * 64
    path = tmp_path / "stale.json"
    path.write_text(json.dumps(stale), encoding="utf-8")
    with pytest.raises(BenchmarkError, match="worksheet_hash"):
        apply_adjudications(dataset, records, [path, _adjudication(tmp_path, "bob", worksheet, full)])
    with pytest.raises(BenchmarkError, match="distinct"):
        apply_adjudications(dataset, records, [_adjudication(tmp_path, "alice", worksheet, full),
                                               _adjudication(tmp_path, "alice", worksheet, full)])
    with pytest.raises(BenchmarkError, match="independent named reviewer"):
        apply_adjudications(dataset, records, [])


def test_matches_verdicts_require_a_consistent_gold_reference(tmp_path):
    dataset, records, report, worksheet = _mini_with_worksheet(tmp_path)
    decisions = [{"sample_id": entry["sample_id"], "finding_id": finding["finding_id"],
                  "verdict": "matches_positive", "matched_gold_id": f"{entry['sample_id']}:pos"}
                 for entry in worksheet["samples"] for finding in entry["unknown_findings"]]
    updated, updated_records, record = apply_adjudications(
        dataset, records, [_adjudication(tmp_path, "alice", worksheet, decisions),
                           _adjudication(tmp_path, "bob", worksheet, decisions)])
    for entry in worksheet["samples"]:
        gold = next(s["gold"] for p in updated["projects"] for s in p["samples"] if s["id"] == entry["sample_id"])
        for finding in entry["unknown_findings"]:
            assert finding["finding_id"] in gold["positive_ids"]
    broken = [dict(decision, matched_gold_id="not-in-gold") for decision in decisions]
    with pytest.raises(BenchmarkError, match="matched_gold_id"):
        apply_adjudications(dataset, records, [_adjudication(tmp_path, "alice", worksheet, broken),
                                               _adjudication(tmp_path, "bob", worksheet, broken)])


def test_updated_dataset_and_results_round_trip(tmp_path):
    dataset, records, report, worksheet = _mini_with_worksheet(tmp_path)
    def mixed(sid):
        return [{"sample_id": entry["sample_id"], "finding_id": finding["finding_id"],
                 "verdict": "new_positive" if finding["finding_id"].endswith("unknown-1") else "not_a_vulnerability"}
                for entry in worksheet["samples"] if entry["sample_id"] == sid for finding in entry["unknown_findings"]]
    decisions = mixed("alpha") + mixed("beta")
    updated, updated_records, record = apply_adjudications(
        dataset, records, [_adjudication(tmp_path, "alice", worksheet, decisions),
                           _adjudication(tmp_path, "bob", worksheet, decisions)])
    for entry in worksheet["samples"]:
        gold = next(s["gold"] for p in updated["projects"] for s in p["samples"] if s["id"] == entry["sample_id"])
        assert f"{entry['sample_id']}:unknown-1" in gold["positive_ids"]
        assert f"{entry['sample_id']}:unknown-2" in gold["negative_ids"]
    path = tmp_path / "updated-dataset.json"
    path.write_text(json.dumps(updated, ensure_ascii=False), encoding="utf-8")
    assert load_dataset(path)["id"] == dataset["id"], "backfilled gold must pass standard dataset validation"
    rebuilt = build_report(report, updated, updated_records, record)
    assert rebuilt["dataset_hash"] == record["updated_dataset_hash"] != report["dataset_hash"]
    assert len(rebuilt["records"]) == len(records)
    assert set(rebuilt["summary"]["arms"]) == {r["arm"] for r in records}
