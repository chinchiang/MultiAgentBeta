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
