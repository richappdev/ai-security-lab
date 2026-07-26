# Evidence Manifest Schema

## Manifest (stored as JSON; indexed in PostgreSQL)

```json
{
  "manifest_version": "1",
  "evidence_id": "uuid",
  "organization_id": "uuid",
  "project_id": "uuid",
  "run_id": "uuid",
  "created_at": "2026-07-26T00:00:00Z",
  "status": "sealed",
  "result": "pass|fail",
  "artifact_versions": {
    "scenario_id": "unauthorized_tool_invocation",
    "scenario_version": "1.0.0",
    "agent_version": "1.0.0",
    "policy_version": "1.0.0"
  },
  "content_hashes": {
    "events": "sha256:...",
    "findings": "sha256:...",
    "redacted_trace": "sha256:..."
  },
  "redaction_map": {
    "fields": ["authorization", "api_key", "password"]
  },
  "objects": [
    {
      "name": "events.json",
      "sha256": "...",
      "uri": "s3://bucket/org/project/run/events.json",
      "content_type": "application/json"
    }
  ],
  "signature": null
}
```

## Product Core vs Private Beta

| Field | Product Core | Private Beta |
|---|---|---|
| Manifest + hashes in PostgreSQL | Required | Required |
| Inline redacted event snapshot | Allowed | Prefer object store |
| MinIO/S3 object URIs | Optional / null | Required |
| Cryptographic signature | Optional | Required for release export |
| Retention state | `pending`/`sealed` | + `expired`/`purged` |

## Invariants

- Ownership (`organization_id`, `project_id`, `run_id`) is mandatory.
- Hash covers the sealed payload bytes after redaction.
- Release-gating results without a sealed manifest are incomplete.
