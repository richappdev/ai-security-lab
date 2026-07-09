# Docker Security Testing Lab Plan

## Goal

Build a local, repeatable, and legally safe testing environment for developing a security testing app. All active scanning, brute force, exploit automation, DDoS simulation, and lateral-movement testing must stay inside authorized lab targets.

## Current Lab Stack

- Docker Compose for orchestration
- OWASP Juice Shop at `http://127.0.0.1:3000`
- DVWA at `http://127.0.0.1:8080`
- Docker bridge network: `ai-security-lab-net`
- Local target allowlist: `targets.allowlist`
- PowerShell helper scripts in `scripts/`
- Python safety guard for allowlist and local-lab target checks
- JSONL audit logging under `logs/`
- Passive tools: `inspect_headers`, `inspect_cookies`, `discover_forms`
- Active low-risk tools: `lab_xss_reflection_check`, `lab_http_methods_check`, `lab_route_exists_check`
- FastAPI `security-app` service at `http://127.0.0.1:8000`

## Implementation Status

Completed:

- Lab target compose stack and lifecycle scripts.
- `security-app` FastAPI skeleton with health check, static UI, passive endpoint, and low-risk active endpoints.
- `targets.allowlist` as the source of truth for approved lab targets.
- `safety/scope_guard.py` for exact allowlist validation and local-lab host enforcement.
- `safety/audit_log.py` for append-only JSONL audit records.
- `tools/passive/headers.py` for passive response header inspection.
- `tools/passive/cookies.py` for passive cookie attribute inspection.
- `tools/passive/forms.py` for passive same-page form discovery without submission.
- `safety/policy.py` and `safety/rate_limit.py` for policy-backed execution limits.
- `tools/active/xss_lab_check.py` for a harmless reflected-input lab check.
- `tools/active/http_methods_check.py` for a one-request HTTP OPTIONS method check.
- `tools/active/route_exists_check.py` for a one-request known-route existence check.
- Static UI exposure for the route existence check.
- In-process FastAPI job registry with job status and cancellation endpoints.
- Markdown report writer for scan results under `reports/`.
- Unit tests for scope rejection, audit logging, policy/rate-limit enforcement, passive tool output shape, and low-risk active check behavior.

Not started:

- SQLite-backed audit storage.
- Multi-request or long-running active scans.
- Redis/Celery-backed background execution.

## Safety Boundary

- Test only targets listed in `targets.allowlist`.
- Keep exposed lab ports bound to `127.0.0.1`.
- Do not scan or attack public IPs, public Taiwan websites, government sites, schools, companies, or unknown third-party assets.
- Require explicit allowlist checks before any active module runs.
- Require allowlist checks, rate limits, timeouts, risk labels, and audit logs for every active test.
- Require in-process job-registry cancellation support before adding multi-request or long-running active tests.
- Require an extra confirmation step before high-risk modules run.

## MVP Scope

1. Start and verify the Docker lab.
2. Read targets from `targets.allowlist`.
3. Add passive target checks.
4. Add low-rate active scans against Juice Shop and DVWA only.
5. Generate a basic report with findings, evidence, and remediation notes.
6. Add audit logging for target, module, start time, end time, result, and operator.

## Suggested App Tech Stack

### Minimal Version

- Backend: Python FastAPI
- Storage: SQLite
- Runtime: Docker Compose
- Reports: Markdown or HTML
- Target control: file-based allowlist

### Expanded Version

- Backend: FastAPI
- Worker queue: Celery
- Queue backend: Redis
- Database: PostgreSQL
- Frontend: React or Next.js
- Reports: HTML and PDF export
- Auth: local admin login or SSO integration

## Compose Layout Target

```text
docker-compose.yml
+-- security-app
|   +-- FastAPI
|   +-- scanner modules
|   +-- report generator
+-- juice-shop
+-- dvwa
+-- postgres  (future, only when SQLite is insufficient)
+-- redis     (future, only when background jobs are needed)
```

The current repository has the lab targets and the `security-app` service. PostgreSQL and Redis should be added only when audit/reporting query needs or background jobs justify the extra runtime complexity.

## Testing Phases

### Phase 1: Passive Checks

- Confirm target is reachable.
- Capture response headers.
- Identify server hints and framework clues.
- Record page title and basic metadata.
- Discover forms without submitting payloads.
- No exploit payloads.

### Phase 2: Low-Risk Active Checks

- Single-route existence checks with strict rate limits.
- Directory and bulk route discovery only after stop/cancel support exists.
- Basic misconfiguration checks.
- Safe vulnerability probes against lab URLs only.
- Current single-request checks are timeout-bound; explicit cancellation is required before this phase expands to multi-request scans.

### Phase 3: Controlled Attack Modules

- SQL injection checks against DVWA and Juice Shop.
- XSS checks against known vulnerable lab forms.
- Weak credential testing with tiny wordlists and low rates.
- Per-module timeout and cancellation.

### Phase 4: High-Risk Modules

- Automated exploit validation.
- Lateral-movement simulation.
- DDoS or stress simulation.

These must run only in a separate isolated lab profile with stricter limits and explicit confirmation.

## Guardrails Status Before Expanding Active Testing

- Done: parse and enforce `targets.allowlist`.
- Done: reject non-localhost/non-lab-local targets and exact non-allowlisted URLs by default.
- Done: enforce policy-backed timeout and request-rate limits in current tools.
- Done: write append-only JSONL audit records.
- Done: label results as `passive` or `active-low-risk`.
- Done: document that current single-request active tools are timeout-bound.
- Done: define in-process stop/cancel support before adding multi-request or long-running active modules.
- Later: add SQLite-backed audit storage when queryability is needed.

## Next Milestones

1. Keep `PLAN.md`, `README.md`, `docs/architecture.md`, and `tools/manifest.yml` synchronized as the source of truth for implementation status.
2. Require future bulk route checks, crawlers, or other multi-request active modules to use the in-process job/cancel model.
3. Move audit logging to SQLite only when queryability is needed.
4. Add Redis/Celery only after background jobs need process isolation or durable queues.

## Active Cancellation Boundary

Current single-request active tools are timeout-bound and run synchronously:

- `lab_xss_reflection_check`
- `lab_http_methods_check`
- `lab_route_exists_check`

Multi-request active tools must not be added unless they use the in-process job registry and cancellation token. Bulk route discovery, crawling, credential checks, exploit validation, and long-running probes must expose job status and support cancellation between network requests and before report writing. Redis/Celery remains a future option only when durable or cross-process background work is justified.

Job control API:

- `GET /jobs/{job_id}` returns job status, timestamps, target, tool, operator, and result or error when available.
- `POST /jobs/{job_id}/cancel` requests cancellation for queued or running jobs and returns the updated job status.

## Operating Commands

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-prereqs.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\start-lab.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\stop-lab.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\reset-lab.ps1
```

## Test Command

```powershell
python -m unittest discover -s tests
```
