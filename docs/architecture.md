# Architecture

This repository is a local AI-assisted security testing lab. It provides intentionally vulnerable Docker targets, a local FastAPI security app, guarded security tools, safety policy, audit logging, and reports.

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

- `docker-compose.yml`: local lab targets and `security-app`.
- `app/`: FastAPI API, static UI, and service wiring for guarded tool execution.
- `targets.allowlist`: approved lab targets.
- `scripts/`: local lab lifecycle commands.
- `docs/`: agent-readable operating instructions and contracts.
- `agents/`: future agent prompts and planning logic.
- `tools/`: passive inspection and low-risk active security tool implementations.
- `safety/`: allowlist, policy, rate-limit, and audit controls.
- `reports/`: generated scan reports and findings.

## Active Execution Boundary

Current active checks are single-request, low-risk modules that are bounded by allowlist validation, policy-backed timeout and rate limits, and audit logging. Timeout is the effective stop boundary for these synchronous checks. Explicit stop/cancel support is required before adding multi-request or long-running active modules.

Implemented active-low-risk modules:

- `lab_xss_reflection_check`: harmless reflected-input marker check.
- `lab_http_methods_check`: one-request HTTP OPTIONS method check.
- `lab_route_exists_check`: one-request HEAD check for one known route path.

## Lab Targets

- OWASP Juice Shop at `http://127.0.0.1:3000`
- DVWA at `http://127.0.0.1:8080`

All lab services should stay bound to localhost unless the operator intentionally changes `.env` for an isolated trusted network.
