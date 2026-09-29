"""Budget-matched, project-separated benchmark runner; synthetic results are never efficacy evidence."""
from __future__ import annotations

import argparse
import asyncio
import ast
import hashlib
import json
import random
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path

from jsonschema import validate

from .schemas import BENCHMARK_DATASET_SCHEMA, BENCHMARK_OBSERVATION_SCHEMA

ARMS = ("traditional", "single_a", "single_b", "single_c", "same_model_repeat", "heterogeneous_independent", "debate")
DEFAULT_BUDGET = {"max_tokens": 12000, "max_seconds": 60, "max_requests": 12, "max_model_calls": 6}
DEFAULT_DATASET = Path(__file__).resolve().parents[2] / "benchmarks" / "synthetic-v1.json"


class BenchmarkError(ValueError):
    pass


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_dataset(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    validate(data, BENCHMARK_DATASET_SCHEMA)
    families, project_ids, sample_ids = {}, set(), set()
    for project in data["projects"]:
        if project["id"] in project_ids:
            raise BenchmarkError("Duplicate project")
        project_ids.add(project["id"])
        if families.setdefault(project["family"], project["split"]) != project["split"]:
            raise BenchmarkError("Related projects/forks cannot cross train/validation/test splits")
        for sample in project["samples"]:
            if sample["id"] in sample_ids:
                raise BenchmarkError("Sample IDs must be globally unique")
            sample_ids.add(sample["id"])
            gold = sample["gold"]
            if set(gold["positive_ids"]) & set(gold["negative_ids"]):
                raise BenchmarkError("Gold positive/negative labels overlap")
            if data["synthetic"] and not gold["synthetic"]:
                raise BenchmarkError("Synthetic dataset cannot contain real gold claims")
            if gold["human_reviewed"] and len(set(gold["reviewers"])) < 2:
                raise BenchmarkError("Gold requires two independent named human reviewers")
            if gold["oracle_verified"] and not gold["oracle_evidence"]:
                raise BenchmarkError("Oracle verification requires evidence references")
            for responses in sample["responses"].values():
                for response in responses:
                    validate(response, BENCHMARK_OBSERVATION_SCHEMA)
    return data


def schedule(dataset, repetitions=3, seed=731, split="test"):
    if not 1 <= repetitions <= 100 or split not in {"train", "validation", "test"}:
        raise BenchmarkError("Invalid repetition count or split")
    rng = random.Random(seed)
    jobs = []
    for project in dataset["projects"]:
        if project["split"] != split:
            continue
        for sample in project["samples"]:
            for repetition in range(repetitions):
                arm_order = list(ARMS)
                rng.shuffle(arm_order)
                for arm in arm_order:
                    jobs.append({"project_id": project["id"], "sample_id": sample["id"], "repetition": repetition,
                                 "arm": arm, "pair_id": f"{project['id']}/{sample['id']}/{repetition}"})
    if not jobs:
        raise BenchmarkError("No projects in the requested split")
    return jobs


def arm_steps(arm):
    if arm == "traditional":
        return [("traditional", "independent")]
    if arm.startswith("single_"):
        return [(arm[-1], "independent")]
    if arm == "same_model_repeat":
        return [("a", "independent")] * 3
    if arm == "heterogeneous_independent":
        return [(model, "independent") for model in "abc"]
    if arm == "debate":
        return [(model, "independent") for model in "abc"] + [("debate", "debate")]
    raise BenchmarkError("Unknown benchmark arm")


def _blocked(reason):
    return {"finding_ids": [], "reproduced_ids": [], "status": "blocked", "tokens": 0, "requests": 0,
            "model_calls": 0, "latency_seconds": 0, "cost_usd": None, "reason": reason}


def traditional_ast(input_data):
    """Real, intentionally narrow static baseline: parse supplied Python, never execute it."""
    start = time.perf_counter()
    findings = []
    files = input_data.get("files", [])
    if len(files) > 100 or sum(len(f.get("content", "")) for f in files) > 1_000_000:
        return _blocked("Builtin AST baseline source bounds exceeded")
    for file in files:
        if not file["path"].endswith(".py"):
            continue
        try:
            tree = ast.parse(file["content"])
        except (SyntaxError, ValueError, MemoryError, RecursionError):
            return {**_blocked("Python parsing failed; no clean result inferred"), "status": "incomplete"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                findings.append(f"ast:{node.func.id}:{file['path']}:{node.lineno}")
    return {"finding_ids": sorted(set(findings)), "reproduced_ids": [], "status": "completed", "tokens": 0,
            "requests": 0, "model_calls": 0, "latency_seconds": time.perf_counter() - start, "cost_usd": 0.0,
            "reason": "Actual stdlib Python AST heuristic; no data-flow proof, target execution or dynamic reproduction"}


def compute_metrics(final_ids, reproduced_ids, independent_reviews, gold, completed):
    predicted, positive, negative = set(final_ids), set(gold["positive_ids"]), set(gold["negative_ids"])
    tp, fp, fn = len(predicted & positive), len(predicted & negative), len(positive - predicted)
    unknown = predicted - positive - negative
    supports = Counter(f for review in independent_reviews for f in set(review))
    minority = {f for f, support in supports.items() if support == 1 and f in positive}
    common_missed = positive - set(supports) if len(independent_reviews) >= 2 else None
    return {"tp": tp, "fp": fp, "fn": fn, "unadjudicated_ids": sorted(unknown),
            "precision": tp / (tp + fp) if tp + fp and not unknown else None,
            "recall": tp / len(positive) if positive else None,
            "common_miss_rate": len(common_missed) / len(positive) if common_missed is not None and positive else None,
            "common_missed_ids": sorted(common_missed) if common_missed is not None else None,
            "minority_retention": len(minority & predicted) / len(minority) if minority and len(independent_reviews) >= 2 else None,
            "minority_positive_ids": sorted(minority) if len(independent_reviews) >= 2 else [],
            "reproduce_rate": len(set(reproduced_ids) & predicted & positive) / tp if tp else None,
            "completion": int(completed)}


def run_job(job, sample, budget, mode):
    start = time.perf_counter()
    consumed = {"tokens": 0, "requests": 0, "model_calls": 0, "latency_seconds": 0.0}
    steps, reviews, final, reproduced, observations, issues = arm_steps(job["arm"]), [], set(), set(), [], []
    counters = Counter()
    for index, (model, phase) in enumerate(steps):
        # Identical initial input, no gold, and no peer outputs in any independent audit.
        view = {"input": sample["input"], "peer_reviews": reviews if phase == "debate" else []}
        step_cap = {"tokens": budget["max_tokens"] // len(steps), "requests": budget["max_requests"] // len(steps),
                    "model_calls": budget["max_model_calls"] // len(steps), "latency_seconds": budget["max_seconds"] / len(steps)}
        if time.perf_counter() - start > budget["max_seconds"]:
            response = _blocked("Measured wall-time budget exhausted")
        elif mode == "synthetic":
            fixtures = sample["responses"].get(model, [])
            offset = job["repetition"] + counters[model]
            response = dict(fixtures[offset % len(fixtures)]) if fixtures else _blocked("Missing declared synthetic response")
        elif model == "traditional":
            response = traditional_ast(sample["input"])
        else:
            response = _blocked("Real model benchmark blocked: no authorized provider execution adapter and human-adjudicated gold configured")
        counters[model] += 1
        validate(response, BENCHMARK_OBSERVATION_SCHEMA)
        over = [key for key in consumed if response[key] > step_cap[key]]
        if over:
            # Fixture reservations are rejected before accepting outputs. No live calls occur in this runner.
            issues.append("Step allocation exceeded: " + ",".join(over))
            response = _blocked(issues[-1])
        for key in consumed:
            consumed[key] += response[key]
        if response["status"] != "completed":
            issues.append(response.get("reason", response["status"]))
        else:
            if phase == "independent":
                reviews.append(list(response["finding_ids"]))
                final.update(response["finding_ids"])
            else:
                final = set(response["finding_ids"])
            reproduced.update(response["reproduced_ids"])
        observations.append({"step": index, "model_alias": model, "phase": phase, "allocation": step_cap,
                             "input_hash": _digest(view), "sealed_output_hash": _digest(response), "response": response,
                             "simulated": mode == "synthetic"})
    completed = not issues and len(observations) == len(steps)
    gold = sample["gold"]
    eligible = not gold["synthetic"] and gold["human_reviewed"] and len(set(gold["reviewers"])) >= 2 and gold["oracle_verified"] and bool(gold["oracle_evidence"])
    computed = compute_metrics(final, reproduced, reviews, gold, completed)
    real_model_arm = job["arm"] != "traditional" and mode != "synthetic"
    blocked = real_model_arm or all(o["response"]["status"] == "blocked" for o in observations)
    valid_efficacy = eligible and mode != "synthetic" and not blocked
    costs = [o["response"]["cost_usd"] for o in observations]
    return job | {"status": "blocked" if blocked else "completed" if completed else "incomplete",
                  "budget": budget.copy(), "usage": consumed, "measured_wall_seconds": time.perf_counter() - start,
                  "cost_usd": sum(costs) if all(c is not None for c in costs) else None,
                  "observations": observations, "finding_ids": sorted(final), "reproduced_ids": sorted(reproduced & final),
                  "metrics": computed if valid_efficacy else None,
                  "preview_metrics": computed if not blocked else None, "gold_eligible": eligible,
                  "simulated": mode == "synthetic", "issues": issues,
                  "limitation": None if valid_efficacy else "No efficacy claim: synthetic, unreviewed gold or unavailable real model execution"}


def summarize(records):
    arms = {}
    for arm in ARMS:
        rows = [r for r in records if r["arm"] == arm]
        usable = [r["metrics"] for r in rows if r["metrics"] is not None]
        previews = [r["preview_metrics"] for r in rows if r["preview_metrics"] is not None]
        def mean_metrics(items):
            return {key: statistics.mean(values) if (values := [i[key] for i in items if i[key] is not None]) else None
                    for key in ["precision", "recall", "common_miss_rate", "minority_retention", "reproduce_rate", "completion"]}
        arms[arm] = {"scheduled": len(rows), "completed": sum(r["status"] == "completed" for r in rows),
                     "blocked": sum(r["status"] == "blocked" for r in rows),
                     "metrics": mean_metrics(usable) if usable else None,
                     "preview_metrics": mean_metrics(previews) if previews else None,
                     "tokens": sum(r["usage"]["tokens"] for r in rows),
                     "requests": sum(r["usage"]["requests"] for r in rows),
                     "model_calls": sum(r["usage"]["model_calls"] for r in rows),
                     "latency_seconds": sum(r["usage"]["latency_seconds"] for r in rows),
                     "cost_usd": sum(r["cost_usd"] for r in rows) if all(r["cost_usd"] is not None for r in rows) else None}
    by_pair = defaultdict(dict)
    for row in records:
        by_pair[row["pair_id"]][row["arm"]] = row
    paired = []
    for pair_id, members in by_pair.items():
        reference = members.get("single_a")
        if not reference:
            continue
        for arm, row in members.items():
            if arm == "single_a":
                continue
            efficacy = row["metrics"] is not None and reference["metrics"] is not None
            left, right = row["metrics"] or row["preview_metrics"], reference["metrics"] or reference["preview_metrics"]
            delta = {k: left[k] - right[k] if left and right and left[k] is not None and right[k] is not None else None
                     for k in ["precision", "recall", "reproduce_rate", "completion"]}
            paired.append({"pair_id": pair_id, "arm": arm, "reference": "single_a", "efficacy_eligible": efficacy,
                           "paired_differences": delta})
    return {"arms": arms, "paired_comparisons": paired,
            "inference": "No superiority or bias-reduction inference. Paired differences are descriptive; repeated samples are not independent projects."}


def run_benchmark(dataset_path=DEFAULT_DATASET, output_dir=None, *, mode="synthetic", repetitions=3, seed=731, split="test", budget=None,
                  profiles=None, model_policy=None, tool_runner=None, model_runner=None):
    if mode not in {"synthetic", "local_tools", "live"}:
        raise BenchmarkError("Unknown benchmark mode")
    budget = dict(DEFAULT_BUDGET if budget is None else budget)
    if set(budget) != set(DEFAULT_BUDGET) or any(not isinstance(v, int) or v <= 0 for v in budget.values()):
        raise BenchmarkError("All four positive integer budget limits are required")
    if mode == "live":
        return asyncio.run(run_live_benchmark(dataset_path, output_dir, repetitions=repetitions, seed=seed, split=split,
                                             budget=budget, profiles=profiles, model_policy=model_policy,
                                             tool_runner=tool_runner, model_runner=model_runner))
    dataset = load_dataset(dataset_path)
    jobs = schedule(dataset, repetitions, seed, split)
    samples = {s["id"]: s for p in dataset["projects"] for s in p["samples"]}
    records = [run_job(job, samples[job["sample_id"]], budget, mode) for job in jobs]
    report = {"schema_version": 1, "dataset_id": dataset["id"], "dataset_hash": _digest(dataset),
              "mode": mode, "seed": seed, "split": split, "repetitions": repetitions, "budget": budget,
              "protocol": "Identical per-arm caps; token/request/call/time budget divided evenly across steps, not multiplied by agent count. Actual spend may differ.",
              "status": "incomplete" if any(r["status"] != "completed" for r in records) else "completed",
              "efficacy_status": "not_established", "schedule": jobs, "records": records, "summary": summarize(records),
              "limitations": ["Bundled gold and model responses are synthetic and await independent human review.",
                              "Real provider effects are blocked until authorized execution adapters, provider manifests and reviewed oracle labels are supplied.",
                              "Builtin AST baseline is a narrow real traditional heuristic, not Semgrep/CodeQL or comprehensive SAST.",
                              "Cost null means unavailable; synthetic fixture costs are not actual billing.",
                              "Project-family split blocks related forks across splits, but cannot rule out unknown model training contamination."]}
    if output_dir is not None:
        destination = Path(output_dir)
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (destination / "results.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records), encoding="utf-8")
    return report


MODEL_FINDINGS_SCHEMA = {"type": "object", "additionalProperties": False, "required": ["finding_ids", "rationale"],
                         "properties": {"finding_ids": {"type": "array", "maxItems": 200, "uniqueItems": True,
                                                        "items": {"type": "string", "maxLength": 300}},
                                        "rationale": {"type": "string", "maxLength": 30000}}}


async def run_live_benchmark(dataset_path=DEFAULT_DATASET, output_dir=None, *, repetitions=3, seed=731, split="test", budget=None,
                             profiles=None, model_policy=None, tool_runner=None, model_runner=None):
    """Execute authorized real model strategies with injected, trusted async tool/model runners.

    tool_runner(input_data, budget) -> BENCHMARK_OBSERVATION_SCHEMA.
    model_runner(profile, system, payload, policy) -> providers.generate_json result.
    Callbacks are host configuration, never imported from data or model output.
    """
    from .domain import ModelProfile
    from .providers import generate_json, ProviderError
    budget = dict(DEFAULT_BUDGET if budget is None else budget)
    if set(budget) != set(DEFAULT_BUDGET) or any(type(v) is not int or v <= 0 for v in budget.values()):
        raise BenchmarkError("All four positive integer budget limits are required")
    profiles = {alias: ModelProfile.model_validate(profile).model_dump() for alias, profile in (profiles or {}).items()}
    if set(profiles) - {"a", "b", "c"} or any(p["provider"] == "demo" for p in profiles.values()):
        raise BenchmarkError("Live profiles use a/b/c aliases and real providers only")
    model_policy = dict(model_policy or {})
    model_runner = model_runner or generate_json
    async def builtin_runner(input_data, _budget):
        return traditional_ast(input_data)
    tool_runner = tool_runner or builtin_runner
    dataset = load_dataset(dataset_path)
    jobs = schedule(dataset, repetitions, seed, split)
    samples = {s["id"]: s for p in dataset["projects"] for s in p["samples"]}
    contexts, records = {}, []
    for job in jobs:
        sample = samples[job["sample_id"]]
        if job["pair_id"] not in contexts:
            tool_budget = budget | {"max_seconds": max(1, budget["max_seconds"] // 4)}
            started = time.perf_counter()
            try:
                context = await asyncio.wait_for(tool_runner(sample["input"], tool_budget.copy()), timeout=tool_budget["max_seconds"])
                validate(context, BENCHMARK_OBSERVATION_SCHEMA)
                context = json.loads(json.dumps(context))
                context["latency_seconds"] = max(context["latency_seconds"], time.perf_counter() - started)
                for metric, cap in [("tokens", "max_tokens"), ("requests", "max_requests"), ("model_calls", "max_model_calls"), ("latency_seconds", "max_seconds")]:
                    if context[metric] > tool_budget[cap]:
                        raise BenchmarkError("Tool runner exceeded its declared budget")
            except Exception:
                context = _blocked("Trusted tool runner failed validation, timed out or exceeded budget; no clean tool context available")
                context.update(tokens=tool_budget["max_tokens"], requests=tool_budget["max_requests"],
                               model_calls=tool_budget["max_model_calls"], latency_seconds=time.perf_counter() - started)
            contexts[job["pair_id"]] = context
        context = contexts[job["pair_id"]]
        start = time.perf_counter()
        usage = {key: context[key] for key in ["tokens", "requests", "model_calls", "latency_seconds"]}
        steps = [] if job["arm"] == "traditional" else arm_steps(job["arm"])
        observations, reviews, final, issues = [], [], set(context["finding_ids"]) if not steps else set(), []
        costs = [context["cost_usd"]]
        if context["status"] != "completed":
            issues.append(context.get("reason", "Shared tool context incomplete"))
        unique_profiles = {(p["provider"], p["model_id"], p["endpoint"]) for p in profiles.values()}
        unique_families = {p["family"].casefold() for p in profiles.values()}
        if job["arm"] in {"heterogeneous_independent", "debate"} and (len(unique_profiles) != 3 or len(unique_families) != 3):
            issues.append("Heterogeneous strategies require three distinct exact model configurations and declared families")
        for index, (alias, phase) in enumerate(steps):
            profile = profiles.get("a" if alias == "debate" else alias)
            caps = {"max_tokens": max(0, (budget["max_tokens"] - context["tokens"]) // len(steps)),
                    "max_model_calls": max(0, (budget["max_model_calls"] - context["model_calls"]) // len(steps)),
                    "max_requests": max(0, (budget["max_requests"] - context["requests"]) // len(steps)),
                    "max_seconds": max(0, (budget["max_seconds"] - context["latency_seconds"]) / len(steps))}
            payload = {"input": sample["input"], "tool_context": context,
                       "peer_reviews": [{"reviewer": f"sealed-{i+1}", "finding_ids": r} for i, r in enumerate(reviews)] if phase == "debate" else []}
            response = _blocked("Missing exact profile or explicit model policy")
            data = None
            step_start = time.perf_counter()
            can_call = (not issues and profile is not None and model_policy.get("data_policy") in {"local_only", "cloud_allowed"}
                        and caps["max_tokens"] > 0 and caps["max_model_calls"] > 0 and caps["max_seconds"] > 0)
            if can_call:
                policy = model_policy | {"max_tokens": caps["max_tokens"], "max_model_calls": caps["max_model_calls"],
                                          "timeout_seconds": caps["max_seconds"], "response_schema": MODEL_FINDINGS_SCHEMA}
                exact = profile | {"max_output_tokens": min(profile["max_output_tokens"], caps["max_tokens"])}
                prompt = ("Audit the provided code and common tool evidence for security issues. Use stable issue locators from the input's issue_id_convention, "
                          "or rule:file:line when none is supplied. Preserve uncertainty in rationale. Never claim to execute tools or reproduce vulnerabilities. "
                          "Do not infer gold labels. " + ("Adjudicate the sealed anonymized candidate reviews against source evidence; votes alone are not proof." if phase == "debate" else "Review independently without peer opinions."))
                try:
                    result = await asyncio.wait_for(model_runner(exact, prompt, payload, policy), timeout=caps["max_seconds"])
                    data = result["data"]
                    validate(data, MODEL_FINDINGS_SCHEMA)
                    actual = result["usage"]
                    response = {"finding_ids": data["finding_ids"], "reproduced_ids": [], "status": "completed",
                                "tokens": actual["tokens"], "model_calls": actual["model_calls"], "requests": 0,
                                "latency_seconds": time.perf_counter() - step_start, "cost_usd": actual.get("cost_usd"),
                                "reason": "Provider output schema validated; reproduction not attempted by model"}
                    validate(response, BENCHMARK_OBSERVATION_SCHEMA)
                except ProviderError as exc:
                    actual = getattr(exc, "usage", None) or {}
                    response = _blocked("Provider blocked or failed: " + str(getattr(exc, "code", "provider_error")))
                    response.update(tokens=actual.get("tokens", caps["max_tokens"]) if actual.get("tokens_known", True) else caps["max_tokens"], model_calls=actual.get("model_calls", caps["max_model_calls"]),
                                    latency_seconds=time.perf_counter() - step_start)
                except Exception:
                    response = _blocked("Model call timed out or returned an invalid contract; reserved usage retained, no retry")
                    response.update(tokens=caps["max_tokens"], model_calls=caps["max_model_calls"], latency_seconds=time.perf_counter() - step_start)
            elif issues:
                response = _blocked(issues[-1])
            validate(response, BENCHMARK_OBSERVATION_SCHEMA)
            if response["tokens"] > caps["max_tokens"] or response["model_calls"] > caps["max_model_calls"] or response["latency_seconds"] > caps["max_seconds"]:
                response = response | {"status": "incomplete", "finding_ids": [], "reason": "Observed usage exceeded step budget; result withheld, usage preserved"}
            for key in usage:
                usage[key] += response[key]
            costs.append(response["cost_usd"])
            if response["status"] != "completed":
                issues.append(response["reason"])
            elif phase == "independent":
                reviews.append(response["finding_ids"])
                final.update(response["finding_ids"])
            else:
                final = set(response["finding_ids"])
            observations.append({"step": index, "phase": phase, "model_alias": alias, "profile": profile,
                                 "allocation": caps, "input_hash": _digest(payload), "sealed_output_hash": _digest(response),
                                 "response": response, "rationale": data.get("rationale") if data else None, "simulated": False})
        complete = not issues
        gold = sample["gold"]
        eligible = not gold["synthetic"] and gold["human_reviewed"] and len(set(gold["reviewers"])) >= 2 and gold["oracle_verified"] and bool(gold["oracle_evidence"])
        reproduced = set(context["reproduced_ids"]) & final
        computed = compute_metrics(final, reproduced, reviews, gold, complete)
        # Static review itself cannot establish dynamic reproduction.
        if not context["reproduced_ids"]:
            computed["reproduce_rate"] = None
        blocked = bool(issues) and not any(o["response"]["status"] == "completed" for o in observations)
        records.append(job | {"status": "blocked" if blocked else "completed" if complete else "incomplete",
                              "budget": budget.copy(), "usage": usage, "measured_wall_seconds": time.perf_counter() - start,
                              "cost_usd": sum(costs) if all(c is not None for c in costs) else None,
                              "tool_context_hash": _digest(context), "observations": observations, "finding_ids": sorted(final),
                              "reproduced_ids": sorted(reproduced), "metrics": computed if eligible and not blocked else None,
                              "preview_metrics": computed if not blocked else None, "gold_eligible": eligible, "simulated": False,
                              "issues": issues, "limitation": None if eligible else "Gold is synthetic or awaits two human reviews and oracle verification"})
    report = {"schema_version": 1, "dataset_id": dataset["id"], "dataset_hash": _digest(dataset), "mode": "live",
              "seed": seed, "split": split, "repetitions": repetitions, "budget": budget, "profiles": profiles,
              "policy": {k: model_policy.get(k) for k in ["data_policy", "allowed_model_origins"]},
              "protocol": "Same frozen tool context per paired sample. Its usage charged to every arm; remaining total budget divided across model steps. Real context execution happens once per pair.",
              "status": "completed" if all(r["status"] == "completed" for r in records) else "incomplete",
              "efficacy_status": "descriptive_only" if any(r["metrics"] is not None for r in records) else "not_established",
              "schedule": jobs, "records": records, "shared_tool_contexts": contexts, "summary": summarize(records),
              "limitations": ["No superiority inference; human-reviewed oracle gold is mandatory for efficacy metrics.",
                              "The default traditional tool is a narrow AST heuristic; inject a trusted sandbox tool_runner for Semgrep/OSV/Gitleaks.",
                              "Model outputs cannot claim dynamic reproduction. Only the trusted tool runner may provide reproduced IDs.",
                              "Per-arm resource summaries charge the common tool artifact to every arm; shared tools physically execute once per pair.",
                              "Provider errors with unknown usage conservatively reserve the full step allocation; no benchmark-layer retries."]}
    if output_dir is not None:
        path = Path(output_dir)
        path.mkdir(parents=True, exist_ok=True)
        (path / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (path / "results.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records), encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=["synthetic", "local_tools", "live"], default="synthetic")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--seed", type=int, default=731)
    parser.add_argument("--split", choices=["train", "validation", "test"], default="test")
    parser.add_argument("--config", type=Path, help="Live JSON with profiles {a,b,c} and model_policy; environment variable names only, never keys")
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8")) if args.config else {}
    if set(config) - {"profiles", "model_policy"}:
        raise BenchmarkError("Unknown live config fields")
    result = run_benchmark(args.dataset, args.output, mode=args.mode, repetitions=args.repetitions, seed=args.seed, split=args.split, **config)
    print(json.dumps({"status": result["status"], "efficacy_status": result["efficacy_status"], "jobs": len(result["records"]), "mode": args.mode}))


if __name__ == "__main__":
    main()
