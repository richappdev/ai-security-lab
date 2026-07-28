"""Evaluate measured pilot outcomes against the Private Beta rollout gates."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class MetricGate:
    name: str
    passed: bool
    observed: Any
    requirement: str


def evaluate_scorecard(metrics: dict[str, Any]) -> dict[str, Any]:
    gates = [
        MetricGate(
            "scenario-reproducibility",
            float(metrics.get("scenario_reproducibility_rate", 0)) >= 0.95,
            metrics.get("scenario_reproducibility_rate"),
            ">= 0.95",
        ),
        MetricGate(
            "evidence-completeness",
            float(metrics.get("evidence_completeness_rate", 0)) == 1.0,
            metrics.get("evidence_completeness_rate"),
            "== 1.0",
        ),
        MetricGate(
            "cross-tenant-denials",
            float(metrics.get("cross_tenant_denial_rate", 0)) == 1.0,
            metrics.get("cross_tenant_denial_rate"),
            "== 1.0",
        ),
        MetricGate(
            "cancellation-latency",
            float(metrics.get("cancellation_p95_seconds", float("inf"))) < 10,
            metrics.get("cancellation_p95_seconds"),
            "< 10 seconds",
        ),
        MetricGate(
            "worker-recovery",
            bool(metrics.get("worker_failure_recovery_succeeded")),
            metrics.get("worker_failure_recovery_succeeded"),
            "true",
        ),
        MetricGate(
            "redaction-defects",
            int(metrics.get("seeded_secret_leaks", -1)) == 0,
            metrics.get("seeded_secret_leaks"),
            "== 0",
        ),
        MetricGate(
            "beta-exit-workflow",
            bool(metrics.get("fail_remediate_pass_completed")),
            metrics.get("fail_remediate_pass_completed"),
            "true",
        ),
    ]
    return {
        "passed": all(gate.passed for gate in gates),
        "gates": [asdict(gate) for gate in gates],
        "product_metrics": {
            key: metrics.get(key)
            for key in (
                "time_to_first_useful_evaluation_minutes",
                "median_release_validation_minutes",
                "mean_remediation_hours",
                "release_decision_usage_rate",
                "false_positive_rate",
                "cost_per_completed_evaluation",
            )
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metrics", type=Path, help="pilot metrics JSON")
    parser.add_argument("--output", type=Path, help="optional scorecard output")
    args = parser.parse_args()
    result = evaluate_scorecard(json.loads(args.metrics.read_text(encoding="utf-8")))
    encoded = json.dumps(result, indent=2, sort_keys=True)
    print(encoded)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
