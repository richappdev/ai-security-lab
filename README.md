# AI Security Lab

Local Docker testing environment for security-tool development. This lab is for authorized testing only and should stay bound to localhost by default.

## Repository Layout

```text
app/       Local FastAPI security app, static UI, and API service wiring.
agents/    AI agent prompts, planner orchestration (manifest/plan/bridge), and instructions.
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
7. `agents/` (`build_plan` / `execute_plan` — never call lab targets directly)

## Included Targets

- OWASP Juice Shop at `http://127.0.0.1:3000`
- DVWA at `http://127.0.0.1:8080`
- Security app API at `http://127.0.0.1:8000`

Both target services are placed on a Docker bridge network named `ai-security-lab-net`. Host access is limited to localhost ports through the compose port bindings. Use `127.0.0.1` or `localhost` from host tools such as browsers, PowerShell, and direct host-side Python commands. Use the `.local` aliases, such as `http://juice-shop.local:3000` and `http://dvwa.local`, when the containerized API is the component making the request.

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

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs on pushes and pull requests to `main`/`master`:

- **test** — Python 3.12, `pip install -r requirements.txt`, then `python -m unittest discover -s tests -v`
- **docker** — `docker compose config`, `docker compose build security-app`, then a standalone container smoke that polls `GET /health` until `"status":"ok"`

Local equivalents:

```powershell
python -m unittest discover -s tests -v
docker compose config
docker compose build security-app
```

After a local build, smoke the image without the full lab stack:

```powershell
docker compose run -d --no-deps --name security-app-ci --service-ports `
  -e DATABASE_URL=sqlite+pysqlite:////tmp/ci.db `
  -e ALLOW_DEV_AUTH=true `
  -e EVIDENCE_SIGNING_KEY=ci-smoke-key `
  security-app
curl http://127.0.0.1:8000/health
docker rm -f security-app-ci
```

## Current Implementation

**MVP status:** Complete as of 2026-07-26. The guarded local lab, agent planner,
passive and bounded active checks, cancellation path, audit trail, reports, unit
suite, and live smoke coverage are verified.

- `app/api/main.py` exposes the local FastAPI skeleton, static UI, passive scan endpoints (headers, cookies, forms), and low-risk active endpoints.
- `safety/scope_guard.py` enforces exact allowlist matching and local-lab host constraints before tool network access.
- `safety/audit_log.py` writes append-only JSONL audit records under `logs/`.
- `tools/passive/headers.py` implements passive response header inspection.
- `tools/passive/cookies.py` implements passive cookie attribute inspection.
- `tools/passive/forms.py` implements passive same-page form discovery without submitting forms.
- `tools/active/xss_lab_check.py` implements a harmless reflected-input check for allowlisted lab targets.
- `tools/active/http_methods_check.py` implements a one-request OPTIONS method check for allowlisted lab targets.
- `tools/active/route_exists_check.py` implements a one-request HEAD route existence check for one known route path on an allowlisted lab target.
- `tools/active/security_header_delta_check.py` implements a fixed two-request security header comparison between root and one known route on an allowlisted lab target.
- `tools/active/auth_page_metadata_check.py` implements a one-request GET-only authentication page metadata check for one known route without submitting credentials.
- `tools/active/bulk_route_exists_check.py` implements a cancellable multi-request HEAD check across a fixed list of known DVWA/Juice Shop paths.
- `reports/writer.py` generates basic Markdown scan reports under `reports/`.
- `safety/cancellation.py` and `app/api/jobs.py` provide cancellation tokens and an in-process job registry for multi-request tools.
- `POST /scan/active/bulk-route-exists` returns a `job_id`; poll `/jobs/{job_id}` or cancel via `/jobs/{job_id}/cancel` (UI: `/ui/jobs.html`).
- `tests/` covers scope checks, audit logging, policy/rate-limit enforcement, passive tool output shape, low-risk active checks, and cancellable bulk jobs.

The existing HTTP checks are now a stable target-adapter pack. Do not add another
HTTP scanner endpoint unless a concrete, reviewed agent-security scenario requires
it.

## Product Core (Agent Security Validation)

Control-plane modules for tenant-aware agent evaluation:

- `docs/product/` — glossary, threat model, scenario/event/evidence contracts
- `domain/`, `persistence/` — SQLAlchemy models, Alembic, RBAC repositories, Postgres RLS hooks
- `scenarios/packs/` — eight deterministic scenarios (confused-deputy, injection, exfil, approval, cancel, MCP poisoning, cost ceiling)
- `agents/adapters/synthetic.py` — vendor-neutral synthetic agent under test
- `evidence/` — sealed manifests + local/MinIO blob store
- `POST /v1/...` — organizations, projects, agents, runs, suite-runs
- Compose: `postgres` always; Keycloak via `--profile oidc`; MinIO via `--profile beta`
- Local auth for lab/tests: `X-User-Sub` header (OIDC JWT when `OIDC_ISSUER` is set)

```powershell
pip install -r requirements.txt
$env:DATABASE_URL = "sqlite+pysqlite:///./tmp/dev.db"   # or use Compose postgres
python -m unittest discover -s tests
```

## Safety Boundary

Private Beta now includes immutable revisions, Temporal-compatible event-driven runs,
run-scoped capabilities, PostgreSQL RLS, Ed25519-capable evidence, retention,
persisted regression comparisons, expiring exceptions, and encrypted CI installations.
See [`docs/product/private-beta-operations.md`](docs/product/private-beta-operations.md)
for deployment, backup/restore, key rotation, incident response, and rollout gates.

## Partner beta certification

The post-implementation gate is executable:

```powershell
python -m certification.readiness --profile beta
python -m certification.readiness --profile beta --live --base-url $env:BETA_BASE_URL
python -m certification.beta_exit --provider $env:CI_INTEGRATION_PROVIDER
python -m certification.scorecard deploy/beta/pilot-metrics.example.json
```

PostgreSQL migrations and RLS can be tested without host dependencies or the
development database:

```powershell
docker compose --profile test up --build --abort-on-container-exit --exit-code-from postgres-test postgres-test
docker compose --profile test rm --stop --force postgres-test postgres-test-db
```

The live gate validates managed PostgreSQL/Alembic/RLS, OIDC, Temporal Cloud,
S3, API, telemetry, signing, and CI configuration as one environment. The
beta-exit command proves fail, remediation, unchanged-suite pass,
cross-tenant denial, redaction, cancellation latency, CI enforcement, and
offline signed-evidence verification. See `deploy/beta/README.md`.

- Test only the targets in `targets.allowlist`.
- Keep `.env` bind addresses set to `127.0.0.1`.
- Do not point scanning, brute force, exploit, DDoS, or lateral-movement modules at public IPs or third-party domains.
- Add rate limits and timeouts to every active test module.
- Current fixed-size active tools are timeout-bound; multi-request active tools (starting with bulk known-route exists) must use the job registry and cancellation token.
- Keep audit logs for target, module, start time, end time, and result.

## Suggested MVP Flow

1. Start this lab with Docker Compose.
2. Confirm both targets load in the browser.
3. Wire your app to read `targets.allowlist`.
4. Implement passive checks first.
5. Add low-rate active scans only against these lab URLs.
6. Add high-risk modules only after allowlist, timeout, cancellation, and audit logging are working.
