# Architecture

This repository is a local AI-assisted security testing lab. It provides intentionally vulnerable Docker targets and a planned structure for an AI security agent, guarded security tools, safety policy, audit logging, and reports.

## Core Principle

Agents do not perform security actions directly. Agents create plans and request tool execution. Tools must check scope, policy, rate limits, timeouts, and audit logging before touching a target.

## Runtime Flow

```text
User request
  -> agent reads docs/runbook.md
  -> agent checks docs/safety-rules.md
  -> planner selects tools from tools/manifest.yml
  -> tool validates target with safety/scope_guard.py
  -> tool executes with timeout and rate limits
  -> safety/audit_log.py records the action
  -> report is written under reports/
```

## Current Components

- `docker-compose.yml`: local lab targets.
- `targets.allowlist`: approved lab targets.
- `scripts/`: local lab lifecycle commands.
- `docs/`: agent-readable operating instructions and contracts.
- `agents/`: future agent prompts and planning logic.
- `tools/`: future passive and active security tool implementations.
- `safety/`: future allowlist, policy, rate-limit, and audit controls.
- `reports/`: generated scan reports and findings.

## Lab Targets

- OWASP Juice Shop at `http://127.0.0.1:3000`
- DVWA at `http://127.0.0.1:8080`

All lab services should stay bound to localhost unless the operator intentionally changes `.env` for an isolated trusted network.
