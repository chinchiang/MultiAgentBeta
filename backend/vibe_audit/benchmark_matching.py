"""Blind-review matching tool: turn unadjudicated benchmark findings into reviewed gold.

Two independent named reviewers adjudicate a blinded worksheet (no strategy/arm
identity). Agreement backfills gold; disagreements need an explicit arbiter. The
tool records declarations only — it cannot prove that the named reviews occurred,
and synthetic fixtures stay ineligible for formal efficacy metrics.
"""
from __future__ import annotations

import argparse
import json
import unicodedata
from pathlib import Path

from jsonschema import validate

from .benchmark import DEFAULT_DATASET, BenchmarkError, _digest, compute_metrics, summarize
from .schemas import BENCHMARK_DATASET_SCHEMA, MATCHING_ADJUDICATION_SCHEMA, MATCHING_WORKSHEET_SCHEMA

VERDICTS = ("matches_positive", "matches_negative", "new_positive", "not_a_vulnerability")


def _canonical_name(name):
    """NFKC + trim + casefold so ' alice'/'ALICE'/homoglyphs cannot pose as a second reviewer."""
    return unicodedata.normalize("NFKC", name).strip().casefold()


def build_worksheet(dataset, records):
    """Blinded per-sample worksheet of unadjudicated findings; no arm, alias, repetition or pair identity."""
    samples = {s["id"]: s for p in dataset["projects"] for s in p["samples"]}
    by_sample = {}
    for record in records:
        by_sample.setdefault(record["sample_id"], []).append(record)
    entries = []
    for sample_id, rows in sorted(by_sample.items()):
        gold = samples[sample_id]["gold"]
        positive, negative = set(gold["positive_ids"]), set(gold["negative_ids"])
        unknowns = {}
        for row in rows:
            for finding_id in row["finding_ids"]:
                if finding_id in positive or finding_id in negative:
                    continue
                entry = unknowns.setdefault(finding_id, {"finding_id": finding_id, "reported_by_runs": 0,
                                                         "reproduced": False, "rationales": set()})
                entry["reported_by_runs"] += 1
                entry["reproduced"] = entry["reproduced"] or finding_id in row["reproduced_ids"]
                for observation in row["observations"]:
                    # Debate rationales discuss peer reviews and would unblind strategy identity;
                    # only independent steps that actually reported this finding may contribute.
                    if observation.get("phase") != "independent":
                        continue
                    if finding_id not in observation.get("response", {}).get("finding_ids", []):
                        continue
                    rationale = observation.get("rationale")
                    if rationale:
                        entry["rationales"].add(rationale)
        if not unknowns:
            continue
        entries.append({"project_id": next(p["id"] for p in dataset["projects"] for s in p["samples"] if s["id"] == sample_id),
                        "sample_id": sample_id, "input": samples[sample_id]["input"],
                        "gold": {"positive_ids": sorted(positive), "negative_ids": sorted(negative)},
                        "unknown_findings": [{"finding_id": e["finding_id"], "reported_by_runs": e["reported_by_runs"],
                                              "reproduced": e["reproduced"], "rationales": sorted(e["rationales"])}
                                             for e in sorted(unknowns.values(), key=lambda e: e["finding_id"])]})
    worksheet = {"schema_version": 1, "dataset_id": dataset["id"], "dataset_hash": _digest(dataset),
                 "results_hash": _digest(records),
                 "instructions": ("Review each unknown finding against the sample source and gold references. Decide one verdict per "
                                  "finding without knowledge of which strategy produced it. Two independent named reviewers must "
                                  "submit separate adjudication files covering every unknown finding."),
                 "samples": entries}
    validate(worksheet, MATCHING_WORKSHEET_SCHEMA)
    return worksheet


def _load_adjudication(path, worksheet_hash, expected_ids, complete=True):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    validate(data, MATCHING_ADJUDICATION_SCHEMA)
    data["reviewer"] = _canonical_name(data["reviewer"])
    if data["worksheet_hash"] != worksheet_hash:
        raise BenchmarkError(f"{Path(path).name}: worksheet_hash does not match the rebuilt blinded worksheet")
    seen = set()
    for decision in data["decisions"]:
        key = (decision["sample_id"], decision["finding_id"])
        if decision["verdict"] not in VERDICTS:
            raise BenchmarkError(f"Unknown verdict {decision['verdict']!r}")
        if key in seen:
            raise BenchmarkError(f"Duplicate decision for {key}")
        if key not in expected_ids:
            raise BenchmarkError(f"{Path(path).name}: {key} is not an unadjudicated finding in the worksheet")
        seen.add(key)
    missing = expected_ids - seen
    if complete and missing:
        raise BenchmarkError(f"{Path(path).name}: adjudication incomplete; missing decisions for {sorted(missing)}")
    return data


def _verdict_is_positive(verdict):
    return verdict in {"matches_positive", "new_positive"}


def apply_adjudications(dataset, records, reviewer_paths, arbiter_paths=(), mode="synthetic"):
    """Merge reviewer decisions into gold, recompute metrics; all-or-nothing on unresolved disagreements."""
    worksheet = build_worksheet(dataset, records)
    worksheet_hash = _digest(worksheet)
    expected_ids = {(entry["sample_id"], finding["finding_id"]) for entry in worksheet["samples"] for finding in entry["unknown_findings"]}
    if not reviewer_paths:
        raise BenchmarkError("Two independent named reviewer adjudication files are required")
    reviewers = [_load_adjudication(path, worksheet_hash, expected_ids) for path in reviewer_paths]
    names = [r["reviewer"] for r in reviewers]
    if len(set(names)) != len(names) or any(not name for name in names):
        raise BenchmarkError("Reviewer names must be non-empty and distinct")
    arbiters = [_load_adjudication(path, worksheet_hash, expected_ids, complete=False) for path in arbiter_paths]
    arbiter_names = [a["reviewer"] for a in arbiters]
    if len(set(arbiter_names)) != len(arbiter_names) or set(arbiter_names) & set(names):
        raise BenchmarkError("Arbiter names must be distinct from each other and from the reviewers")
    dataset = json.loads(json.dumps(dataset, ensure_ascii=False))
    samples = {s["id"]: s for p in dataset["projects"] for s in p["samples"]}
    decisions, unresolved = {}, {}
    def _decision(owner, key):
        return next(d for d in owner["decisions"] if (d["sample_id"], d["finding_id"]) == key)
    for key in sorted(expected_ids):
        verdicts = {r["reviewer"]: _decision(r, key)["verdict"] for r in reviewers}
        unique = set(verdicts.values())
        if len(unique) == 1:
            decisions[key] = {"verdict": unique.pop(), "resolution": "agreed", "reviewers": verdicts}
        else:
            arbiter = next((a for a in arbiters if any((d["sample_id"], d["finding_id"]) == key for d in a["decisions"])), None)
            if arbiter is None:
                unresolved[key] = verdicts
            else:
                resolved = _decision(arbiter, key)
                decisions[key] = {"verdict": resolved["verdict"], "resolution": "arbitrated",
                                  "reviewers": verdicts, "arbiter": arbiter["reviewer"]}
    if unresolved:
        raise BenchmarkError("Unresolved disagreements need an arbiter decision for: " +
                             ", ".join(f"{s}/{f}" for s, f in sorted(unresolved)))
    matched = {}
    for entry in worksheet["samples"]:
        gold = samples[entry["sample_id"]]["gold"]
        matched[entry["sample_id"]] = {"positive": set(gold["positive_ids"]), "negative": set(gold["negative_ids"])}
    applied = []
    for (sample_id, finding_id), decision in decisions.items():
        verdict, detail = decision["verdict"], {}
        if verdict in {"matches_positive", "matches_negative"}:
            if decision["resolution"] == "arbitrated":
                owner = next(a for a in arbiters if a["reviewer"] == decision["arbiter"])
                targets = {owner["reviewer"]: _decision(owner, (sample_id, finding_id)).get("matched_gold_id")}
            else:
                targets = {owner["reviewer"]: _decision(owner, (sample_id, finding_id)).get("matched_gold_id") for owner in reviewers}
            pool = matched[sample_id]["positive"] if verdict == "matches_positive" else matched[sample_id]["negative"]
            if len(set(targets.values())) != 1 or next(iter(targets.values())) not in pool:
                raise BenchmarkError(f"{sample_id}/{finding_id}: {verdict} requires one matched_gold_id "
                                     f"present in the corresponding gold list")
            detail["matched_gold_id"] = next(iter(targets.values()))
        if _verdict_is_positive(verdict):
            matched[sample_id]["positive"].add(finding_id)
        else:
            matched[sample_id]["negative"].add(finding_id)
        if finding_id in matched[sample_id]["positive"] and finding_id in matched[sample_id]["negative"]:
            raise BenchmarkError(f"{sample_id}/{finding_id}: gold positive/negative labels overlap")
        applied.append({"sample_id": sample_id, "finding_id": finding_id, "verdict": verdict, "resolution": decision["resolution"],
                        "reviewers": decision["reviewers"], **({"arbiter": decision["arbiter"]} if decision["resolution"] == "arbitrated" else {}),
                        **detail})
    for entry in worksheet["samples"]:
        gold = samples[entry["sample_id"]]["gold"]
        gold["positive_ids"] = sorted(matched[entry["sample_id"]]["positive"])
        gold["negative_ids"] = sorted(matched[entry["sample_id"]]["negative"])
        gold["human_reviewed"] = True
        gold["reviewers"] = sorted(set(gold["reviewers"]) | set(names) | set(arbiter_names))
    validate(dataset, BENCHMARK_DATASET_SCHEMA)
    updated_records = [_recompute(record, samples[record["sample_id"]]["gold"], mode) for record in records]
    counts = {"decisions": len(applied), "agreed": sum(a["resolution"] == "agreed" for a in applied),
              "arbitrated": sum(a["resolution"] == "arbitrated" for a in applied)}
    record = {"schema_version": 1, "dataset_id": dataset["id"], "original_dataset_hash": worksheet["dataset_hash"],
              "updated_dataset_hash": _digest(dataset), "results_hash": worksheet["results_hash"],
              "worksheet_hash": worksheet_hash, "reviewers": sorted(set(names)), "arbiters": sorted(set(arbiter_names)),
              "counts": counts, "decisions": sorted(applied, key=lambda a: (a["sample_id"], a["finding_id"])),
              "declaration": "This record documents adjudication declarations. The tool cannot prove that the named reviews occurred."}
    return dataset, updated_records, record


def _recompute(record, gold, mode):
    """Recompute one record's metrics against updated gold; run status and usage are preserved."""
    final, reproduced = record["finding_ids"], record["reproduced_ids"]
    reviews = [o["response"]["finding_ids"] for o in record["observations"]
               if o["phase"] == "independent" and o["response"]["status"] == "completed"]
    completed = record["status"] == "completed"
    computed = compute_metrics(set(final), set(reproduced), reviews, gold, completed)
    # Live runs with no tool-side reproduction must keep "not attempted" (null), not 0.0.
    if record.get("tool_context_hash") is not None and not reproduced:
        computed["reproduce_rate"] = None
    eligible = (not gold["synthetic"] and gold["human_reviewed"] and len(set(gold["reviewers"])) >= 2
                and gold["oracle_verified"] and bool(gold["oracle_evidence"]))
    updated = dict(record)
    if record.get("tool_context_hash") is not None:
        blocked = record["status"] == "blocked"
        valid = eligible and completed
        updated["metrics"] = computed if valid else None
        updated["preview_metrics"] = computed if not blocked else None
        updated["gold_eligible"] = eligible
        updated["limitation"] = None if valid else "Unfinished run; partial findings are not scored" if eligible else record["limitation"]
    else:
        blocked = record["status"] == "blocked"
        valid = eligible and mode != "synthetic" and not blocked and completed
        updated["metrics"] = computed if valid else None
        updated["preview_metrics"] = computed if not blocked else None
        updated["gold_eligible"] = eligible
        updated["limitation"] = None if valid else record["limitation"]
    return updated


def build_report(report, dataset, updated_records, matching_record):
    """Rebuilt report: updated records/summary, adjudication provenance, recomputed efficacy status."""
    updated = dict(report)
    updated["dataset_hash"] = matching_record["updated_dataset_hash"]
    updated["records"] = updated_records
    updated["summary"] = summarize(updated_records)
    mode = report["mode"]
    if mode == "live":
        updated["efficacy_status"] = "descriptive_only" if any(r["metrics"] is not None for r in updated_records) else "not_established"
    updated["adjudication"] = {key: matching_record[key] for key in
                               ["worksheet_hash", "updated_dataset_hash", "results_hash", "reviewers", "arbiters", "counts"]}
    updated["limitations"] = list(report["limitations"]) + [
        "Metrics were recomputed after two-reviewer human adjudication of previously unadjudicated findings; "
        "the tool records declarations and cannot prove that the named reviews occurred."]
    return updated


def _infer_mode(records):
    if any(record.get("tool_context_hash") is not None for record in records):
        return "live"
    return "local_tools" if any(not record["simulated"] for record in records) else "synthetic"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    worksheet = sub.add_parser("worksheet", help="Generate the blinded review worksheet")
    worksheet.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    worksheet.add_argument("--results", type=Path, required=True, help="results.jsonl from a benchmark run")
    worksheet.add_argument("--output", type=Path, required=True)
    apply = sub.add_parser("apply", help="Apply two-reviewer adjudications and recompute metrics")
    apply.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    apply.add_argument("--results", type=Path, required=True)
    apply.add_argument("--report", type=Path, help="report.json to rebuild alongside the results")
    apply.add_argument("--reviewer", type=Path, action="append", required=True, dest="reviewers")
    apply.add_argument("--arbiter", type=Path, action="append", default=[], dest="arbiters")
    apply.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    from .benchmark import load_dataset
    dataset = load_dataset(args.dataset)
    records = [json.loads(line) for line in args.results.read_text(encoding="utf-8").splitlines() if line.strip()]
    if args.command == "worksheet":
        ws = build_worksheet(dataset, records)
        args.output.write_text(json.dumps(ws, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"worksheet_hash": _digest(ws), "samples": len(ws["samples"]),
                          "unknown_findings": sum(len(s["unknown_findings"]) for s in ws["samples"])}))
        return
    report = None
    if args.report:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        if report.get("records") != records:
            raise BenchmarkError("report.json records do not match the results file")
    mode = report["mode"] if report else _infer_mode(records)
    updated_dataset, updated_records, record = apply_adjudications(dataset, records, args.reviewers, args.arbiters, mode)
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    (out / "dataset-adjudicated.json").write_text(json.dumps(updated_dataset, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "matching-record.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "results-adjudicated.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in updated_records), encoding="utf-8")
    if report is not None:
        (out / "report-adjudicated.json").write_text(
            json.dumps(build_report(report, updated_dataset, updated_records, record), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"decisions": record["counts"]["decisions"], "agreed": record["counts"]["agreed"],
                      "arbitrated": record["counts"]["arbitrated"], "reviewers": record["reviewers"]}))


if __name__ == "__main__":
    main()
