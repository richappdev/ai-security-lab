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
- Active low-risk tools: `lab_xss_reflection_check`, `lab_http_methods_check`, `lab_route_exists_check`, `lab_security_header_delta_check`, `lab_auth_page_metadata_check`, `lab_bulk_route_exists_check`
- FastAPI `security-app` service at `http://127.0.0.1:8000`

## Implementation Status

Completed:

- Lab target compose stack and lifecycle scripts.
- `security-app` FastAPI skeleton with health check, static UI, passive endpoints (headers, cookies, forms), and low-risk active endpoints.
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
- `tools/active/security_header_delta_check.py` for a fixed two-request security header comparison between root and one known route.
- `tools/active/auth_page_metadata_check.py` for a one-request GET-only authentication page metadata check without credential submission.
- `tools/active/bulk_route_exists_check.py` for a cancellable multi-request HEAD check across a fixed list of known DVWA/Juice Shop paths (not open crawling).
- Static UI exposure for the route existence, security header delta, authentication page metadata, and bulk known-route job controls.
- Passive API endpoints for headers, cookies, and forms (`POST /scan/passive/headers`, `/cookies`, `/forms`).
- In-process FastAPI job registry with job status and cancellation endpoints.
- Async job endpoint `POST /scan/active/bulk-route-exists` that returns a `job_id` and checks the cancellation token between requests.
- Markdown report writer for scan results under `reports/`.
- Agent planner orchestration: manifest reader, plan validation, execution bridge via `service.py`, and aggregate multi-tool reports.
- Unit tests for scope rejection, audit logging, policy/rate-limit enforcement, passive tool output shape, low-risk active check behavior, bulk cancellable job behavior, and agent plan → execute → audit → report.
- Current verification: `py -m unittest discover -s tests` passes with 108 tests run and 17 skipped.

Not started:

- SQLite-backed audit storage.
- Credential checks, exploit validation, or high-volume crawling.
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

## Implementation Phases

### Phase 1: Documentation Reconciliation

Priority: High

Tasks:

- Update `PLAN.md` so completed items match the current codebase.
- Move `security-app` from future compose target to current stack.
- Add `lab_http_methods_check` and `lab_route_exists_check` to completed active checks.
- Replace stale next milestones with the actual next work.
- Update `docs/architecture.md` so `tools/`, `safety/`, and `reports/` are no longer described as future-only components.
- Verify `README.md`, `app/README.md`, and `tools/manifest.yml` agree on exposed endpoints and implemented tools.

Acceptance criteria:

- No doc says `security-app` is future work.
- No doc says the HTTP methods check is not started.
- The next milestone list reflects current implementation reality.
- `python -m unittest discover -s tests` still passes.

### Phase 2: Active Execution Controls

Priority: Completed for the MVP foundation; required for future multi-request active checks

Implemented:

- Chose an in-process FastAPI job registry instead of Redis/Celery for the next milestone.
- Added job states: `queued`, `running`, `completed`, `failed`, `cancel_requested`, and `cancelled`.
- Added a cancellation token contract for future long-running tools.
- Added `GET /jobs/{job_id}` and `POST /jobs/{job_id}/cancel`.
- Kept current single-request scan endpoints synchronous, timeout-bound, and audited.
- Added deterministic tests for job creation, read, completion, failure, cancellation, terminal-state behavior, and a cancellable fake multi-step job.

Acceptance criteria:

- Multi-request active modules must use the in-process job registry and cancellation token before they are added.
- Current one-request active modules remain timeout-bound and audited.
- Redis/Celery remains deferred until durable or cross-process background execution is justified.

### Phase 3: Next Low-Risk Active Check

Priority: Medium

Completed in this phase:

- Safe route existence check against known lab-local paths via `lab_route_exists_check`.
- Security header delta check between root and one known application route via `lab_security_header_delta_check`.
- Non-mutating authentication page metadata check for DVWA/Juice Shop via `lab_auth_page_metadata_check`.

Candidate checks:

- None selected until the next human review.

Constraints:

- No credential stuffing.
- No destructive requests.
- No public or third-party targets.
- No high-volume crawling.
- Must use `targets.allowlist` before network access.
- Must resolve policy limits before execution.
- Must write audit start and completion records.
- Must be added to `tools/manifest.yml`.
- Must include unit tests for success, scope rejection, policy rejection, and request failure.

Acceptance criteria:

- New tool is reviewed before use against live lab containers.
- API/service wiring exists only after the tool passes isolated tests.
- Generated findings use one of the existing risk labels: `passive`, `active-low-risk`, or `active-high-risk`.

### Phase 4: Audit Storage Evolution

Priority: Medium, only when queryability is needed

Current state:

- Audit logging is append-only JSONL under `logs/audit.jsonl`.

Tasks:

- Define query requirements before introducing SQLite.
- Preserve append-only behavior or provide equivalent tamper-evident semantics.
- Add migration or dual-write strategy if existing JSONL records need to be retained.
- Add tests for audit writes, reads, and failure behavior.

Acceptance criteria:

- SQLite is introduced only with clear reporting/query needs.
- Existing audit fields remain available: run ID, operator, tool, target, risk, start/end time, status, and result summary.

### Phase 5: Background Jobs and Expanded Runtime

Priority: Later

Current state:

- In-process job status and cancellation endpoints already exist for future cancellable tools.

Tasks:

- Add Redis/Celery only after scans need process isolation, durable queues, or cross-process execution.
- Require future long-running tools to use the existing job registry and cancellation token before live use.
- Revisit PostgreSQL only if SQLite is insufficient for audit/reporting needs.

Acceptance criteria:

- Background runtime is justified by tool behavior, not added preemptively.
- The operator can see scan status and stop eligible scans.
- Safety controls remain enforced inside each tool, not only at API boundaries.

## Guardrails Status Before Expanding Active Testing

- Done: parse and enforce `targets.allowlist`.
- Done: reject non-localhost/non-lab-local targets and exact non-allowlisted URLs by default.
- Done: enforce policy-backed timeout and request-rate limits in current tools.
- Done: write append-only JSONL audit records.
- Done: label results as `passive` or `active-low-risk`.
- Done: document that current fixed-size active tools are timeout-bound.
- Done: define in-process stop/cancel support before adding multi-request or long-running active modules.
- Later: add SQLite-backed audit storage when queryability is needed.

## Next Milestones

1. Keep longer-running or higher-risk active modules deferred until they pass human review and reuse the job/cancel contract where needed.
2. Optional: live smoke remaining passive cookies/forms APIs when useful; record in the Security Testing Log.
3. Move audit logging to SQLite only when queryability is needed.
4. Add Redis/Celery only after background jobs need process isolation or durable queues.
5. Continue keeping `PLAN.md`, README files, architecture docs, UI pages, Notion pages, and `tools/manifest.yml` synchronized.

Completed recently:

- Phase A: expose remaining passive tools via API (`/scan/passive/cookies`, `/scan/passive/forms`).
- Phase B: agent planner integration (manifest reader, plan contract, service execution bridge, aggregate reports).
- Phase C: first cancellable multi-request scan (`lab_bulk_route_exists_check` via `POST /scan/active/bulk-route-exists`).
- Live lab smoke (2026-07-14): bulk known-route exists against Juice Shop + DVWA (complete + cancel); logged in Notion Security Testing Log. Rebuild `security-app` before live API smoke if the container image is stale.

## Active Cancellation Boundary

Current single-request active tools are timeout-bound and run synchronously:

- `lab_xss_reflection_check`
- `lab_http_methods_check`
- `lab_route_exists_check`
- `lab_auth_page_metadata_check`

Current fixed two-request active tools are also timeout-bound and run synchronously:

- `lab_security_header_delta_check`

Multi-request active tools must not be added unless they use the in-process job registry and cancellation token. The first cancellable multi-request tool is:

- `lab_bulk_route_exists_check`: fixed-list bulk known-route HEAD checks for DVWA/Juice Shop paths only. Started via `POST /scan/active/bulk-route-exists`, polled via `GET /jobs/{job_id}`, and stopped via `POST /jobs/{job_id}/cancel`. The tool checks the cancellation token between network requests.

Bulk route discovery/crawling, credential checks, exploit validation, and other long-running probes remain deferred. Redis/Celery remains a future option only when durable or cross-process background work is justified.

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
