# Private Beta engineering notes

Implemented foundations:

- **OIDC:** [`deploy/keycloak/aisec-realm.json`](../../deploy/keycloak/aisec-realm.json) imported via `docker compose --profile oidc up`. Set `OIDC_ISSUER` / `OIDC_AUDIENCE`. Lab `X-User-Sub` requires `ALLOW_DEV_AUTH=true` (disable for partner demos).
- **Durable runs:** [`workers/durable.py`](../../workers/durable.py) — capability documents, heartbeats, cancel/recover; suite/run APIs use this when `USE_DURABLE_RUNS=true`. Optional Temporal server: `--profile beta` (`TEMPORAL_HOST`).
- **Evidence:** HMAC-signed manifests + SARIF/JSON export bundles via `/v1/.../runs/{id}/export`. MinIO via `--profile beta` + `MINIO_ENDPOINT`.
- **CI gates:** `POST /v1/.../release-gates` builds GitHub check-run / GitLab status payloads and publishes when tokens are set (otherwise dry-run).
- **Findings UX:** list/patch findings; product UI at `/ui/product.html` with triage + timeline.

Exit gate: design partner fails build → remediate → rerun → pass → export signed evidence bundle.
