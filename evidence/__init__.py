"""Evidence sealing, signing, and SARIF/JSON export bundles."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any
from uuid import uuid4

from domain import GateResult


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def signing_key() -> bytes:
    return os.environ.get("EVIDENCE_SIGNING_KEY", "local-dev-evidence-key").encode("utf-8")


def sign_payload(data: Any) -> str:
    digest = hmac.new(signing_key(), canonical_json(data), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def verify_signature(data: Any, signature: str | None) -> bool:
    if not signature:
        return False
    expected = sign_payload(data)
    return hmac.compare_digest(expected, signature)


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
    sign: bool = True,
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
    manifest: dict[str, Any] = {
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
    if sign:
        unsigned = dict(manifest)
        unsigned["signature"] = None
        manifest["signature"] = sign_payload(unsigned)
    content_hash = sha256_bytes(canonical_json(manifest))
    return manifest, content_hash


def build_sarif(
    *,
    run_id: str,
    scenario_key: str,
    gate_result: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    results = []
    for finding in findings:
        results.append(
            {
                "ruleId": finding.get("assertion_id", "unknown"),
                "level": "error" if finding.get("severity") in {"high", "critical"} else "warning",
                "message": {"text": finding.get("title", "finding")},
                "properties": {
                    "severity": finding.get("severity"),
                    "detail": finding.get("detail", {}),
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ai-security-lab",
                        "informationUri": "https://github.com/richappdev/ai-security-lab",
                        "version": "0.2.0",
                    }
                },
                "result": results,
                "properties": {
                    "run_id": run_id,
                    "scenario_key": scenario_key,
                    "gate_result": gate_result,
                },
            }
        ],
    }


def build_export_bundle(
    *,
    manifest: dict[str, Any],
    events: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    gate_result: str,
    scenario_key: str,
    run_id: str,
) -> dict[str, Any]:
    sarif = build_sarif(
        run_id=run_id,
        scenario_key=scenario_key,
        gate_result=gate_result,
        findings=findings,
    )
    bundle = {
        "bundle_version": "1",
        "manifest": manifest,
        "events": events,
        "findings": findings,
        "sarif": sarif,
    }
    bundle["signature"] = sign_payload({k: v for k, v in bundle.items() if k != "signature"})
    return bundle
