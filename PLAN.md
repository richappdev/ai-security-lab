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

## Safety Boundary

- Test only targets listed in `targets.allowlist`.
- Keep exposed lab ports bound to `127.0.0.1`.
- Do not scan or attack public IPs, public Taiwan websites, government sites, schools, companies, or unknown third-party assets.
- Require explicit allowlist checks before any active module runs.
- Require rate limits, timeouts, cancellation, and audit logs for every active test.
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
+-- postgres
+-- redis
+-- juice-shop
+-- dvwa
```

The current repository has the lab targets. The `security-app`, `postgres`, and `redis` services can be added once the app implementation begins.

## Testing Phases

### Phase 1: Passive Checks

- Confirm target is reachable.
- Capture response headers.
- Identify server hints and framework clues.
- Record page title and basic metadata.
- No exploit payloads.

### Phase 2: Low-Risk Active Checks

- Directory and route discovery with strict rate limits.
- Form discovery.
- Basic misconfiguration checks.
- Safe vulnerability probes against lab URLs only.

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

## Guardrails To Implement Before Active Testing

- Parse and enforce `targets.allowlist`.
- Reject public IP ranges and non-allowlisted domains by default.
- Add per-target and global request rate limits.
- Add max runtime per task.
- Add stop/cancel support.
- Add audit log persistence.
- Add clear result labeling: `passive`, `active-low-risk`, `active-high-risk`.

## Next Milestones

1. Add a `security-app` service skeleton.
2. Implement allowlist loading and URL validation.
3. Add a passive scanner endpoint.
4. Add SQLite audit logging.
5. Add a simple report output folder.
6. Add one safe DVWA/Juice Shop active check.
7. Add Redis/Celery only after background jobs are needed.

## Operating Commands

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-prereqs.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\start-lab.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\stop-lab.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\reset-lab.ps1
```
