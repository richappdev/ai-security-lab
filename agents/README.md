# Agents

This directory is reserved for AI security agent logic, planning code, memory, and prompts.

Agents must follow:

- `docs/agent-contract.md`
- `docs/safety-rules.md`
- `docs/tool-contract.md`
- `safety/policy.yml`

Agents should not send network requests directly. They should select tools from `tools/manifest.yml` and rely on tool-level safety checks.
