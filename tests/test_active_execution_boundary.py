from __future__ import annotations

import unittest
from pathlib import Path


class ActiveExecutionBoundaryTests(unittest.TestCase):
    def test_plan_documents_cancellation_gate_before_multi_request_active_tools(self):
        plan = Path("PLAN.md").read_text(encoding="utf-8")

        self.assertIn("Current single-request active tools are timeout-bound", plan)
        self.assertIn("Multi-request active tools must not be added", plan)

    def test_active_tool_manifest_descriptions_mark_single_request_tools(self):
        manifest = Path("tools/manifest.yml").read_text(encoding="utf-8")

        for tool_name in (
            "lab_xss_reflection_check",
            "lab_http_methods_check",
            "lab_route_exists_check",
        ):
            tool_section_start = manifest.index(f"- name: {tool_name}")
            next_tool_start = manifest.find("\n  - name:", tool_section_start + 1)
            tool_section = manifest[tool_section_start:] if next_tool_start == -1 else manifest[tool_section_start:next_tool_start]
            self.assertIn("single-request", tool_section)


if __name__ == "__main__":
    unittest.main()
