# Tests

Tests prioritize safety boundaries before scanner behavior.

Current coverage:

- Allowlist parsing and scope rejection.
- Audit log writing and failure behavior.
- Policy loading and rate-limit enforcement.
- Passive tool output shape and API endpoints.
- Low-risk active tool behavior and rejection paths.
- Job states, cancellation, and the cancellable bulk-route API.
- Agent plan validation, guarded execution, audit, and aggregate reports.
- Markdown report generation.

Current verification:

```powershell
python -m unittest discover -s tests
```

Result on 2026-07-26: 108 tests run, 17 skipped, OK.
