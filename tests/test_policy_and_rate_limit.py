from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from safety.policy import PolicyError, load_policy, resolve_execution_limits
from safety.rate_limit import RateLimiter


POLICY_TEXT = """version: 1

scope:
  allowed_targets_file: targets.allowlist
  localhost_only_by_default: true
  deny_public_ips: true
  deny_private_network_scan: true
  deny_third_party_domains: true

limits:
  default_timeout_seconds: 10
  max_timeout_seconds: 30
  max_requests_per_minute: 30
  max_same_origin_pages: 25

allowed_activity:
  - passive_http_inspection
  - same_origin_crawl

blocked_activity:
  - public_target_testing

audit:
  required: true
  output_directory: logs
  fields:
    - run_id
    - operator
"""


class PolicyAndRateLimitTests(unittest.TestCase):
    def make_repo(self) -> tempfile.TemporaryDirectory[str]:
        temp_dir = tempfile.TemporaryDirectory()
        root = Path(temp_dir.name)
        (root / "safety").mkdir()
        (root / "safety" / "policy.yml").write_text(POLICY_TEXT, encoding="utf-8")
        return temp_dir

    def test_load_policy_reads_limits_and_lists(self):
        with self.make_repo() as repo:
            policy = load_policy(repo)

        self.assertEqual(policy.version, 1)
        self.assertEqual(policy.limits.default_timeout_seconds, 10)
        self.assertEqual(policy.limits.max_requests_per_minute, 30)
        self.assertIn("passive_http_inspection", policy.allowed_activity)
        self.assertEqual(policy.audit["fields"], ["run_id", "operator"])

    def test_resolve_execution_limits_rejects_values_above_policy(self):
        with self.make_repo() as repo:
            with self.assertRaises(PolicyError):
                resolve_execution_limits(
                    requested_timeout_seconds=31,
                    requested_rate_limit_per_minute=30,
                    repo_root=repo,
                )
            with self.assertRaises(PolicyError):
                resolve_execution_limits(
                    requested_timeout_seconds=10,
                    requested_rate_limit_per_minute=31,
                    repo_root=repo,
                )

    def test_resolve_execution_limits_rejects_zero_values(self):
        with self.make_repo() as repo:
            with self.assertRaises(PolicyError):
                resolve_execution_limits(
                    requested_timeout_seconds=0,
                    requested_rate_limit_per_minute=30,
                    repo_root=repo,
                )
            with self.assertRaises(PolicyError):
                resolve_execution_limits(
                    requested_timeout_seconds=10,
                    requested_rate_limit_per_minute=0,
                    repo_root=repo,
                )

    def test_rate_limiter_waits_between_requests(self):
        times = [0.0, 1.0, 6.0]
        slept: list[float] = []

        def clock() -> float:
            return times.pop(0)

        limiter = RateLimiter(requests_per_minute=10, clock=clock, sleeper=slept.append)
        limiter.wait()
        limiter.wait()

        self.assertEqual(slept, [5.0])


if __name__ == "__main__":
    unittest.main()
