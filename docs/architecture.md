# Architecture

This repository is a local AI-assisted security testing lab. It provides intentionally vulnerable Docker targets, a local FastAPI security app, guarded security tools, safety policy, audit logging, and reports.

## Core Principle

Agents do not perform security actions directly. Agents create plans and request tool execution. Tools must check scope, policy, rate limits, timeouts, and audit logging before touching a target.

## Runtime Flow

```text
User request
  -> agent reads docs/runbook.md
  -> agent checks docs/safety-rules.md
  -> agents/manifest.py loads tools/manifest.yml
  -> agents/planner.py validates tool + target + params
  -> agents/bridge.py calls app/api/service.py helpers
  -> tool validates target with safety/scope_guard.py
  -> tool executes with timeout and rate limits
  -> safety/audit_log.py records the action
  -> aggregate Markdown report is written under reports/
```

## Current Components

- `docker-compose.yml`: local lab targets and `security-app`.
- `app/`: FastAPI API (including `/scan/passive/headers`, `/scan/passive/cookies`, and `/scan/passive/forms`), static UI, and service wiring for guarded tool execution.
- `targets.allowlist`: approved lab targets.
- `scripts/`: local lab lifecycle commands.
- `docs/`: agent-readable operating instructions and contracts.
- `agents/`: prompt templates plus planner orchestration (`manifest.py`, `planner.py`, `bridge.py`).
- `tools/`: passive inspection and low-risk active security tool implementations.
- `safety/`: allowlist, policy, rate-limit, and audit controls.
- `reports/`: generated scan reports and findings.

## Active Execution Boundary

Current active checks are fixed-size, low-risk modules that are bounded by allowlist validation, policy-backed timeout and rate limits, and audit logging. Timeout is the effective stop boundary for these synchronous checks. Multi-request or long-running active modules must run through the in-process job registry and check a cancellation token between network requests.

Implemented active-low-risk modules:

- `lab_xss_reflection_check`: harmless reflected-input marker check.
- `lab_http_methods_check`: one-request HTTP OPTIONS method check.
- `lab_route_exists_check`: one-request HEAD check for one known route path.
- `lab_security_header_delta_check`: fixed two-request GET comparison of security headers between root and one known route.
- `lab_auth_page_metadata_check`: one-request GET-only authentication page metadata check for one known route without credential submission.
- `lab_bulk_route_exists_check`: cancellable multi-request HEAD checks across a fixed list of known DVWA/Juice Shop paths only (`POST /scan/active/bulk-route-exists`).

## Job Control

The FastAPI app exposes a minimal in-process job control surface:

- `POST /scan/active/bulk-route-exists` starts a cancellable bulk known-route job and returns `job_id`.
- `GET /jobs/{job_id}` returns status, timestamps, target, tool, operator, and result or error when available.
- `POST /jobs/{job_id}/cancel` requests cancellation for queued or running work.

Job states are `queued`, `running`, `completed`, `failed`, `cancel_requested`, and `cancelled`. Cancelled jobs write audit records with `status: cancelled`. The Jobs UI at `/ui/jobs.html` polls status and exposes a cancel button.

## Product control plane

In addition to lab scan adapters, the app exposes `/v1` for AI agent security validation:

- Tenant graph and runs persist via SQLAlchemy (`persistence/`) with `organization_id` isolation.
- Deterministic scenarios live under `scenarios/packs/` and execute through `scenarios/runner.py`.
- Synthetic agents under test: `agents/adapters/synthetic.py` (never call lab targets directly for product scenarios).
- Evidence manifests: `evidence/`; optional MinIO via Compose profile `beta`.
- Private Beta foundations: `workers/temporal_stub.py`, `app/api/sse.py`, `integrations/ci_gates.py`, `observability/otel.py`.
- Enterprise stubs: `enterprise/`.

See `docs/product/README.md`.

## Lab Targets

- OWASP Juice Shop at `http://127.0.0.1:3000`
- DVWA at `http://127.0.0.1:8080`

All lab services should stay bound to localhost unless the operator intentionally changes `.env` for an isolated trusted network.
