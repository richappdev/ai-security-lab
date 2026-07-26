"""Evidence manifest hashing and sealing."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import uuid4

from domain import GateResult


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_manifest(
    *,
    organization_id: str,
    project_id: str,
    run_id: str,
    scenario_key: str,
    scenario_version: str,
    agent_version: str,
    gate_result: GateResult,
    events: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    object_uri: str | None = None,
) -> tuple[dict[str, Any], str]:
    events_hash = sha256_bytes(canonical_json(events))
    findings_hash = sha256_bytes(canonical_json(findings))
    evidence_id = str(uuid4())
    objects = []
    if object_uri:
        objects.append(
            {
                "name": "events.json",
                "sha256": events_hash,
                "uri": object_uri,
                "content_type": "application/json",
            }
        )
    manifest = {
        "manifest_version": "1",
        "evidence_id": evidence_id,
        "organization_id": organization_id,
        "project_id": project_id,
        "run_id": run_id,
        "status": "sealed",
        "result": gate_result.value,
        "artifact_versions": {
            "scenario_id": scenario_key,
            "scenario_version": scenario_version,
            "agent_version": agent_version,
            "policy_version": "1.0.0",
        },
        "content_hashes": {
            "events": events_hash,
            "findings": findings_hash,
            "redacted_trace": events_hash,
        },
        "redaction_map": {"fields": ["authorization", "api_key", "password"]},
        "objects": objects,
        "signature": None,
    }
    content_hash = sha256_bytes(canonical_json(manifest))
    return manifest, content_hash
