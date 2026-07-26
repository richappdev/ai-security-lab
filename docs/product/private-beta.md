# Private Beta engineering notes

See the Bigger Roadmap Phase 2. Implemented foundations in-repo:

- `workers/temporal_stub.py` — workflow + capability document interface (swap for Temporal Cloud later)
- `evidence/store.py` — local filesystem + MinIO/S3 via `MINIO_ENDPOINT`
- `integrations/ci_gates.py` — GitHub/GitLab check-run payload builder
- `app/api/sse.py` — SSE run event stream
- `observability/otel.py` — OTLP bootstrap when `OTEL_EXPORTER_OTLP_ENDPOINT` is set
- Compose profile `beta` starts MinIO

Exit gate: design partner fails build → remediate → rerun → pass → export signed evidence bundle.
