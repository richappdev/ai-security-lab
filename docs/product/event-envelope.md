# Normalized Agent / Tool Event Envelope

Provider- and framework-neutral event schema for evaluation runs.

## Envelope

```json
{
  "event_id": "uuid",
  "organization_id": "uuid",
  "project_id": "uuid",
  "run_id": "uuid",
  "seq": 1,
  "ts": "2026-07-26T00:00:00Z",
  "actor": {
    "type": "agent|model|tool|policy|operator|system",
    "id": "string",
    "version": "string|null"
  },
  "type": "model.request|model.response|agent.handoff|tool.discovery|tool.call|tool.result|memory.op|retrieval.op|policy.decision|approval.decision|cost.tick|cancel.signal|scope.change",
  "payload": {},
  "redaction": {
    "applied": true,
    "fields": ["payload.headers.authorization"]
  },
  "cost": {
    "tokens_in": 0,
    "tokens_out": 0,
    "currency_units": 0
  }
}
```

## Event types

| Type | Meaning |
|---|---|
| `model.request` / `model.response` | Model I/O (redacted) |
| `agent.handoff` | Control transfer between agents |
| `tool.discovery` | Tool/MCP catalog observation |
| `tool.call` / `tool.result` | Tool invocation and outcome |
| `memory.op` / `retrieval.op` | Memory write/read or RAG retrieval |
| `policy.decision` | Allow/deny/require-approval |
| `approval.decision` | Human approval outcome |
| `cost.tick` | Incremental cost accounting |
| `cancel.signal` | Cancellation requested/honored |
| `scope.change` | Allowed tools/targets/ceilings changed |

## Invariants

- Events are append-only within a Run.
- `seq` is monotonic per Run.
- Payload must be redacted before persistence when secrets may be present.
- Schema version field may be added as `schema_version` (default `1`).
