from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from reports.writer import (
    render_aggregate_markdown_report,
    render_markdown_report,
    write_markdown_report,
)


class ReportWriterTests(unittest.TestCase):
    def sample_result(self) -> dict:
        return {
            "tool": "inspect_headers",
            "target": "http://127.0.0.1:3000",
            "risk": "passive",
            "status": "completed",
            "http_status": 200,
            "headers": {
                "Server": "fake-lab",
                "X-Frame-Options": "DENY",
            },
            "findings": [
                {
                    "id": "missing_security_header",
                    "severity": "info",
                    "evidence": "Content-Security-Policy header was not present.",
                }
            ],
            "started_at": "2026-07-08T00:00:00Z",
            "ended_at": "2026-07-08T00:00:01Z",
        }

    def test_render_markdown_report_contains_required_sections(self):
        report = render_markdown_report(
            self.sample_result(),
            operator="tester",
            run_id="run-report",
            generated_at="2026-07-08T00:00:02Z",
        )

        self.assertIn("# Security Lab Scan Report", report)
        self.assertIn("## Summary", report)
        self.assertIn("## Findings", report)
        self.assertIn("## Evidence", report)
        self.assertIn("## Remediation Notes", report)
        self.assertIn("## Test Limitations", report)
        self.assertIn("Content-Security-Policy header was not present.", report)

    def test_write_markdown_report_creates_report_file(self):
        with tempfile.TemporaryDirectory() as repo:
            metadata = write_markdown_report(
                self.sample_result(),
                operator="tester",
                run_id="run-report",
                repo_root=repo,
            )
            report_path = Path(metadata["path"])

            self.assertTrue(report_path.exists())
            self.assertEqual(report_path.parent, Path(repo) / "reports")
            self.assertEqual(metadata["format"], "markdown")
            self.assertIn("Security Lab Scan Report", report_path.read_text(encoding="utf-8"))

    def test_render_aggregate_markdown_report_combines_tools(self):
        report = render_aggregate_markdown_report(
            {
                "plan_id": "plan-report",
                "objective": "multi-tool",
                "risk_level": "passive",
                "status": "completed",
                "target": "http://127.0.0.1:3000",
                "tools": ["inspect_headers", "inspect_cookies"],
                "results": [
                    self.sample_result(),
                    {
                        "tool": "inspect_cookies",
                        "risk": "passive",
                        "status": "completed",
                        "findings": [],
                        "started_at": "2026-07-08T00:00:00Z",
                        "ended_at": "2026-07-08T00:00:01Z",
                    },
                ],
                "started_at": "2026-07-08T00:00:00Z",
                "ended_at": "2026-07-08T00:00:02Z",
            },
            operator="tester",
            run_id="run-agg",
            generated_at="2026-07-08T00:00:03Z",
        )
        self.assertIn("# Security Lab Aggregate Scan Report", report)
        self.assertIn("`inspect_headers`", report)
        self.assertIn("`inspect_cookies`", report)


if __name__ == "__main__":
    unittest.main()
