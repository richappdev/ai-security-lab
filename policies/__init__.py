"""Versioned release-policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class PolicyDecision:
    allowed: bool
    reasons: list[str]
    metrics: dict[str, Any]


def evaluate_release_policy(
    rules: dict[str, Any],
    *,
    scenario_keys: list[str],
    results: list[dict[str, Any]],
    evidence_complete: bool,
    has_active_exception: bool = False,
) -> PolicyDecision:
    reasons: list[str] = []
    failed = [result for result in results if result.get("gate_result") == "fail"]
    max_failed = int(rules.get("max_failed", 0))
    if len(failed) > max_failed:
        reasons.append(f"failed scenarios {len(failed)} exceeds policy maximum {max_failed}")
    required = set(rules.get("required_scenarios") or [])
    missing = sorted(required - set(scenario_keys))
    if missing:
        reasons.append("missing required scenarios: " + ", ".join(missing))
    block_severities = set(rules.get("block_severities") or ["critical", "high"])
    blocking_findings = [
        finding
        for result in results
        for finding in result.get("findings", [])
        if finding.get("severity", "high") in block_severities
    ]
    if blocking_findings:
        reasons.append(f"{len(blocking_findings)} blocking-severity findings")
    if rules.get("require_complete_evidence", True) and not evidence_complete:
        reasons.append("release-gating evidence is incomplete")
    if reasons and has_active_exception:
        return PolicyDecision(
            allowed=True,
            reasons=["active approved exception"] + reasons,
            metrics={"failed_count": len(failed), "blocking_findings": len(blocking_findings)},
        )
    return PolicyDecision(
        allowed=not reasons,
        reasons=reasons,
        metrics={"failed_count": len(failed), "blocking_findings": len(blocking_findings)},
    )
