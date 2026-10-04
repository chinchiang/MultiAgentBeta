"""Strict, public JSON schemas for catalog and benchmark artifacts only."""

CATALOG_ENTRY_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["id", "official_id", "standard", "version", "title", "source", "license"],
    "properties": {key: {"type": "string", "minLength": 1} for key in
                   ["id", "official_id", "standard", "version", "title", "source", "license"]}
    | {"description": {"type": "string"}, "level": {"type": ["integer", "null"]}},
}

BENCHMARK_DATASET_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["id", "version", "synthetic", "projects"],
    "properties": {
        "id": {"type": "string", "minLength": 1}, "version": {"type": "string"},
        "synthetic": {"type": "boolean"}, "description": {"type": "string"},
        "projects": {"type": "array", "minItems": 1, "items": {
            "type": "object", "additionalProperties": False,
            "required": ["id", "family", "split", "samples"],
            "properties": {
                "id": {"type": "string", "minLength": 1}, "family": {"type": "string", "minLength": 1},
                "split": {"enum": ["train", "validation", "test"]},
                "samples": {"type": "array", "minItems": 1, "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["id", "input", "gold", "responses"],
                    "properties": {
                        "id": {"type": "string", "minLength": 1}, "input": {"type": "object"},
                        "gold": {"type": "object", "additionalProperties": False,
                            "required": ["positive_ids", "negative_ids", "human_reviewed", "reviewers", "oracle_verified", "oracle_evidence", "synthetic"],
                            "properties": {
                                "positive_ids": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
                                "negative_ids": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
                                "human_reviewed": {"type": "boolean"},
                                "reviewers": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
                                "oracle_verified": {"type": "boolean"},
                                "oracle_evidence": {"type": "array", "items": {"type": "string"}},
                                "synthetic": {"type": "boolean"},
                            }},
                        "responses": {"type": "object", "additionalProperties": {"type": "array", "items": {"type": "object"}}},
                    },
                }},
            },
        }},
    },
}

BENCHMARK_OBSERVATION_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["finding_ids", "reproduced_ids", "status", "tokens", "requests", "model_calls", "latency_seconds", "cost_usd"],
    "properties": {
        "finding_ids": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
        "reproduced_ids": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
        "status": {"enum": ["completed", "incomplete", "blocked", "failed"]},
        **{k: {"type": "integer", "minimum": 0} for k in ["tokens", "requests", "model_calls"]},
        "latency_seconds": {"type": "number", "minimum": 0},
        "cost_usd": {"type": ["number", "null"], "minimum": 0},
        "reason": {"type": "string"},
    },
}

MATCHING_WORKSHEET_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["schema_version", "dataset_id", "dataset_hash", "results_hash", "instructions", "samples"],
    "properties": {
        "schema_version": {"const": 1}, "dataset_id": {"type": "string", "minLength": 1},
        "dataset_hash": {"type": "string"}, "results_hash": {"type": "string"},
        "instructions": {"type": "string"},
        "samples": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "required": ["project_id", "sample_id", "input", "gold", "unknown_findings"],
            "properties": {
                "project_id": {"type": "string", "minLength": 1}, "sample_id": {"type": "string", "minLength": 1},
                "input": {"type": "object"},
                "gold": {"type": "object", "additionalProperties": False,
                    "required": ["positive_ids", "negative_ids"],
                    "properties": {"positive_ids": {"type": "array", "items": {"type": "string"}},
                                   "negative_ids": {"type": "array", "items": {"type": "string"}}}},
                "unknown_findings": {"type": "array", "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["finding_id", "reported_by_runs", "reproduced", "rationales"],
                    "properties": {"finding_id": {"type": "string", "minLength": 1},
                                   "reported_by_runs": {"type": "integer", "minimum": 1},
                                   "reproduced": {"type": "boolean"},
                                   "rationales": {"type": "array", "items": {"type": "string"}}}},
                },
            },
        }},
    },
}

MATCHING_ADJUDICATION_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["schema_version", "reviewer", "worksheet_hash", "decisions"],
    "properties": {
        "schema_version": {"const": 1},
        "reviewer": {"type": "string", "minLength": 1},
        "worksheet_hash": {"type": "string", "minLength": 1},
        "decisions": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "required": ["sample_id", "finding_id", "verdict"],
            "properties": {
                "sample_id": {"type": "string", "minLength": 1},
                "finding_id": {"type": "string", "minLength": 1},
                "verdict": {"enum": ["matches_positive", "matches_negative", "new_positive", "not_a_vulnerability"]},
                "matched_gold_id": {"type": ["string", "null"]},
                "notes": {"type": "string"},
            },
        }},
    },
}
