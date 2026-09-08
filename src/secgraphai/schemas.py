"""Versioned public JSON Schemas for reports, attack packs, and runtime policies."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from secgraphai.core import Report

SCHEMA_VERSION = "1.0"

ATTACK_PACK_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://secgraphai.dev/schemas/attack-pack-1.0.json",
    "type": "object",
    "required": ["id", "version", "publisher", "minimum_engine", "attacks"],
    "additionalProperties": False,
    "properties": {
        "id": {"type": "string", "minLength": 1},
        "version": {"type": "string"},
        "publisher": {"type": "string"},
        "minimum_engine": {"type": "string"},
        "trust": {
            "enum": ["TRUSTED_OFFICIAL", "TRUSTED_ORGANIZATION", "UNVERIFIED_COMMUNITY", "LOCAL"]
        },
        "signature": {"type": ["string", "null"]},
        "attacks": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "family", "prompt"],
                "properties": {
                    "id": {"type": "string"},
                    "family": {"type": "string"},
                    "prompt": {"type": "string"},
                    "cost": {"type": "integer", "minimum": 1},
                },
            },
        },
    },
}

POLICY_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://secgraphai.dev/schemas/policy-1.0.json",
    "type": "object",
    "required": ["rules"],
    "additionalProperties": False,
    "properties": {
        "mode": {"enum": ["enforce", "shadow"]},
        "default": {
            "enum": [
                "allow",
                "deny",
                "redact",
                "require_approval",
                "rate_limit",
                "sandbox",
                "log",
                "transform",
            ]
        },
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "effect"],
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string"},
                    "effect": {"type": "string"},
                    "match": {"type": "object"},
                    "reason": {"type": "string"},
                    "priority": {"type": "integer"},
                },
            },
        },
    },
}


def public_schemas() -> dict[str, dict[str, Any]]:
    report = Report.model_json_schema()
    report["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    report["$id"] = "https://secgraphai.dev/schemas/report-1.0.json"
    return {
        "report-1.0.json": report,
        "attack-pack-1.0.json": ATTACK_PACK_SCHEMA,
        "policy-1.0.json": POLICY_SCHEMA,
    }


def write_schemas(directory: str | Path) -> list[Path]:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    result = []
    for name, schema in public_schemas().items():
        target = root / name
        target.write_text(json.dumps(schema, indent=2, sort_keys=True), encoding="utf-8")
        result.append(target)
    return result
