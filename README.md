# AI Security Lab

Local Docker testing environment for security-tool development. This lab is for authorized testing only and should stay bound to localhost by default.

## Repository Layout

```text
app/       Future local security app code.
agents/    AI agent prompts, planner logic, and agent instructions.
docs/      Architecture, runbook, contracts, and safety rules.
lab/       Lab target notes, future compose overlays, and seed data.
safety/    Policy and guard code for allowlists, limits, and audit logs.
scripts/   PowerShell helpers for operating the local lab.
tools/     Passive and active security tool implementations.
reports/   Generated scan reports.
tests/     Safety and tool tests.
```

For AI-agent operation, start with:

1. `docs/runbook.md`
2. `docs/safety-rules.md`
3. `docs/agent-contract.md`
4. `docs/tool-contract.md`
5. `tools/manifest.yml`
6. `safety/policy.yml`

## Included Targets

- OWASP Juice Shop at `http://127.0.0.1:3000`
- DVWA at `http://127.0.0.1:8080`

Both services are placed on a Docker bridge network named `ai-security-lab-net`. Host access is limited to localhost ports through the compose port bindings.

## Requirements

- Docker Desktop
- Docker Compose v2

## Start

```powershell
Copy-Item .env.example .env
docker compose up -d
docker compose ps
```

Open:

- Juice Shop: `http://127.0.0.1:3000`
- DVWA: `http://127.0.0.1:8080`

DVWA's default credentials for this image are usually `admin` / `password`. On first login, initialize or reset the database from DVWA's setup page if prompted.

## Stop

```powershell
docker compose down
```

## Reset

```powershell
docker compose down --volumes
docker compose up -d
```

## Validate

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\validate-lab.ps1
```

## Test

```powershell
python -m unittest discover -s tests
```

## Current Implementation

- `safety/scope_guard.py` enforces exact allowlist matching and local-lab host constraints before tool network access.
- `safety/audit_log.py` writes append-only JSONL audit records under `logs/`.
- `tools/passive/headers.py` implements the first passive tool, `inspect_headers`.
- `tests/test_safety_and_headers.py` covers scope checks, audit logging, and passive tool output shape.

## Safety Boundary

- Test only the targets in `targets.allowlist`.
- Keep `.env` bind addresses set to `127.0.0.1`.
- Do not point scanning, brute force, exploit, DDoS, or lateral-movement modules at public IPs or third-party domains.
- Add rate limits and timeouts to every active test module.
- Keep audit logs for target, module, start time, end time, and result.

## Suggested MVP Flow

1. Start this lab with Docker Compose.
2. Confirm both targets load in the browser.
3. Wire your app to read `targets.allowlist`.
4. Implement passive checks first.
5. Add low-rate active scans only against these lab URLs.
6. Add high-risk modules only after allowlist, timeout, cancellation, and audit logging are working.
