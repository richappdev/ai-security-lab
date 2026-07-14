# Agents

This directory contains AI security agent prompts and the planner orchestration layer.

Agents must follow:

- `docs/agent-contract.md`
- `docs/safety-rules.md`
- `docs/tool-contract.md`
- `safety/policy.yml`

## Orchestration

| Module | Role |
| --- | --- |
| `manifest.py` | Load `tools/manifest.yml` at runtime |
| `planner.py` | Build/validate plans (tool + target + params) against the manifest |
| `bridge.py` | Execute plans through `app/api/service.py` helpers only |

Agents must never send network requests directly to lab targets. They select tools from the manifest and call `execute_plan(...)`, which dispatches to guarded service helpers. Those helpers invoke tools that enforce scope, policy, rate limits, timeouts, and audit logging.

Example:

```python
from agents import build_plan, execute_plan

plan = build_plan(
    target="http://127.0.0.1:3000",
    objective="passive reconnaissance",
    risk_level="passive",
    tools=["inspect_headers", "inspect_cookies"],
)
result = execute_plan(plan, generate_report=True)
```

Multi-tool runs write one aggregate Markdown report under `reports/`.
