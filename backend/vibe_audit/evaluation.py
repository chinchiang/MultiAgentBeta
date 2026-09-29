"""Offline, ground-truth based metrics. Never invent benchmark observations."""
from __future__ import annotations

import math


def wilson(successes: int, total: int) -> list[float] | None:
    if not total:
        return None
    z=1.96
    p=successes/total
    denom=1+z*z/total
    center=(p+z*z/(2*total))/denom
    width=z*math.sqrt(p*(1-p)/total+z*z/(4*total*total))/denom
    return [max(0,center-width),min(1,center+width)]


def compare(gold: list[dict], trials: list[dict]) -> dict:
    """gold: case_id, project_id, vulnerable(bool), split; trials: strategy,
    case_id, detected(bool|null), completed(bool), tokens, seconds, budget_id.
    Unfinished trials are reported, never silently counted as true negatives.
    This computes descriptive pilot metrics, not a significance claim.
    """
    ids={row["case_id"]:row for row in gold}
    if len(ids)!=len(gold) or not gold:
        raise ValueError("Unique nonempty ground-truth cases required")
    if any(type(row.get("vulnerable")) is not bool for row in gold):
        raise ValueError("Ground truth must be independently labeled booleans")
    projects={}
    for row in gold:
        projects.setdefault(row["project_id"],set()).add(row["split"])
    if any(len(s)>1 for s in projects.values()):
        raise ValueError("Project-level train/test split leakage")
    if any(row["case_id"] not in ids for row in trials):
        raise ValueError("Unknown case in benchmark results")
    if len({r["budget_id"] for r in trials})>1:
        raise ValueError("Strategies must use the same declared budget protocol")
    strategies={}
    for trial in trials:
        if type(trial.get("completed")) is not bool or (trial["completed"] and type(trial.get("detected")) is not bool):
            raise ValueError("Completed trials need explicit boolean detections")
        values=strategies.setdefault(trial["strategy"],{"tp":0,"fp":0,"tn":0,"fn":0,"incomplete":0,"tokens":0,"seconds":0,"trials":0})
        values["trials"]+=1
        values["tokens"]+=trial.get("tokens",0)
        values["seconds"]+=trial.get("seconds",0)
        if not trial["completed"]:
            values["incomplete"]+=1
            continue
        actual=ids[trial["case_id"]]["vulnerable"]
        key=("tp" if actual else "fp") if trial["detected"] else ("fn" if actual else "tn")
        values[key]+=1
    for values in strategies.values():
        positive=values["tp"]+values["fp"]
        actual=values["tp"]+values["fn"]
        values["precision"]=values["tp"]/positive if positive else None
        values["recall_completed_trials"]=values["tp"]/actual if actual else None
        values["precision_interval_95"]=wilson(values["tp"],positive)
        values["incomplete_rate"]=values["incomplete"]/values["trials"]
    return {"strategies":strategies,"note":"Descriptive metrics on supplied independent ground truth only. Incomplete trials excluded from confusion matrix and reported separately; intervals assume independent trials and are not valid for correlated repeats without cluster analysis. No multi-model superiority is inferred."}
