"""Evidence sealing, signing, and SARIF/JSON export bundles."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import html
from base64 import b64decode, b64encode
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from domain import GateResult


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def signing_key() -> bytes:
    return os.environ.get("EVIDENCE_SIGNING_KEY", "local-dev-evidence-key").encode("utf-8")


def signing_algorithm() -> str:
    if os.environ.get("EVIDENCE_ED25519_PRIVATE_KEY"):
        return "ed25519"
    return os.environ.get("EVIDENCE_SIGNING_ALGORITHM", "hmac-sha256").lower()


def _ed25519_private_key() -> Ed25519PrivateKey:
    encoded = os.environ.get("EVIDENCE_ED25519_PRIVATE_KEY")
    if encoded:
        return Ed25519PrivateKey.from_private_bytes(b64decode(encoded))
    # Deterministic local-only key. Hosted beta must provide the explicit key.
    seed = hashlib.sha256(signing_key()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def evidence_public_key() -> str | None:
    if signing_algorithm() != "ed25519":
        return None
    raw = _ed25519_private_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64encode(raw).decode("ascii")


def signing_key_id() -> str:
    configured = os.environ.get("EVIDENCE_SIGNING_KEY_ID")
    if configured:
        return configured
    public = evidence_public_key()
    material = public.encode("ascii") if public else signing_key()
    return "key-" + hashlib.sha256(material).hexdigest()[:16]


def sign_payload(data: Any) -> str:
    if signing_algorithm() == "ed25519":
        signature = _ed25519_private_key().sign(canonical_json(data))
        return "ed25519:" + b64encode(signature).decode("ascii")
    digest = hmac.new(signing_key(), canonical_json(data), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def verify_signature(
    data: Any,
    signature: str | None,
    *,
    public_key: str | None = None,
) -> bool:
    if not signature:
        return False
    if signature.startswith("ed25519:"):
        try:
            public = public_key or evidence_public_key()
            if not public:
                return False
            Ed25519PublicKey.from_public_bytes(b64decode(public)).verify(
                b64decode(signature.split(":", 1)[1]),
                canonical_json(data),
            )
            return True
        except (InvalidSignature, ValueError):
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
        "sealed_at": datetime.now(timezone.utc).isoformat(),
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
        "signing": {
            "algorithm": signing_algorithm(),
            "key_id": signing_key_id(),
            "public_key": evidence_public_key(),
        },
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
    html_report = build_html_report(
        run_id=run_id,
        scenario_key=scenario_key,
        gate_result=gate_result,
        findings=findings,
    )
    pdf_report = build_pdf_report(
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
        "html": html_report,
        "pdf_base64": b64encode(pdf_report).decode("ascii"),
    }
    bundle["signature"] = sign_payload({k: v for k, v in bundle.items() if k != "signature"})
    return bundle


def build_html_report(
    *,
    run_id: str,
    scenario_key: str,
    gate_result: str,
    findings: list[dict[str, Any]],
) -> str:
    items = "".join(
        "<li><strong>"
        + html.escape(str(finding.get("severity", "high")))
        + "</strong> "
        + html.escape(str(finding.get("title", "finding")))
        + "</li>"
        for finding in findings
    ) or "<li>No findings</li>"
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Evidence report</title>"
        "<style>body{font-family:sans-serif;max-width:800px;margin:2rem auto}</style></head>"
        f"<body><h1>Agent Security Evidence</h1><p>Run: {html.escape(run_id)}</p>"
        f"<p>Scenario: {html.escape(scenario_key)}</p><p>Gate: {html.escape(gate_result)}</p>"
        f"<h2>Findings</h2><ul>{items}</ul></body></html>"
    )


def build_pdf_report(
    *,
    run_id: str,
    scenario_key: str,
    gate_result: str,
    findings: list[dict[str, Any]],
) -> bytes:
    """Build a compact, dependency-free single-page PDF report."""
    lines = [
        "Agent Security Evidence",
        f"Run: {run_id}",
        f"Scenario: {scenario_key}",
        f"Gate: {gate_result}",
        f"Findings: {len(findings)}",
    ]
    lines.extend(
        f"- [{finding.get('severity', 'high')}] {finding.get('title', 'finding')}"
        for finding in findings[:20]
    )
    escaped = [
        str(line).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        for line in lines
    ]
    stream = "BT /F1 11 Tf 50 760 Td 14 TL " + " T* ".join(
        f"({line}) Tj" for line in escaped
    ) + " ET"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        f"<< /Length {len(stream.encode('latin-1', 'replace'))} >>\nstream\n{stream}\nendstream".encode(
            "latin-1", "replace"
        ),
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode())
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(
        f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return bytes(output)
