# Agent Runbook

Use this runbook when another AI agent or automation system needs to operate this repository.

## Start Here

1. Read `README.md`.
2. Read `docs/safety-rules.md`.
3. Read `docs/agent-contract.md`.
4. Read `docs/tool-contract.md`.
5. Read `tools/manifest.yml`.
6. Read `safety/policy.yml`.
7. Run `scripts/check-prereqs.ps1` before starting the lab.

## Safe Operating Sequence

1. Confirm Docker and Docker Compose are available.
2. Start the lab with `scripts/start-lab.ps1`.
3. Verify Juice Shop and DVWA are reachable on localhost.
4. Load approved targets from `targets.allowlist`.
5. Reject any target not listed in the allowlist.
6. Run passive tools first.
7. Run single-request, low-risk active tools only against approved lab targets.
8. For multi-request checks such as `lab_bulk_route_exists_check`, start the job via `POST /scan/active/bulk-route-exists`, poll `GET /jobs/{job_id}`, and cancel with `POST /jobs/{job_id}/cancel` when needed. Rebuild `security-app` (`docker compose build security-app && docker compose up -d security-app`) before live smoke if OpenAPI is missing newer routes.
9. Write audit logs for every tool call (inside the container at `/workspace/logs/audit.jsonl` when running via Compose).
10. Write reports under `reports/`.
11. Do not add credential checks, exploit validation, or high-volume crawling until those tools pass human review and reuse the job/cancel contract.
12. Record live smoke results in the Notion Security Testing Log (allowlist checks, job IDs, audit refs, false-positive notes).

## Stop Conditions

Stop immediately if:

- The requested target is not in `targets.allowlist`.
- The target resolves to a public IP or third-party domain.
- A tool request asks for denial of service, credential stuffing, destructive exploitation, or lateral movement.
- Rate limits or timeouts are missing for an active tool.
- A multi-request or long-running active tool does not use the job registry and cancellation token.
- Audit logging cannot be written.

## Common Commands

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-prereqs.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\start-lab.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\stop-lab.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\reset-lab.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\validate-lab.ps1
```
