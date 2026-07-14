# Tool Contract

Security tools in this repository must use a consistent contract so agents can call them safely.

## Tool Metadata

Every tool should appear in `tools/manifest.yml` with:

- `name`
- `category`
- `risk`
- `entrypoint`
- `description`
- `requires_network`
- `allowed_targets_file`
- `timeout_seconds`
- `audit_required`

## Input Shape

Tools should accept structured input equivalent to:

```yaml
target: http://127.0.0.1:3000
operator: local-user
run_id: example-run-id
timeout_seconds: 10
rate_limit_per_minute: 30
```

## Output Shape

Tools should return structured output equivalent to:

```yaml
tool: inspect_headers
target: http://127.0.0.1:3000
risk: passive
status: completed
findings:
  - id: missing_security_header
    severity: info
    evidence: Content-Security-Policy header was not present.
started_at: 2026-07-07T00:00:00Z
ended_at: 2026-07-07T00:00:03Z
```

## Required Behavior

Before a tool sends any network request, it must:

1. Load `safety/policy.yml`.
2. Load `targets.allowlist`.
3. Confirm the target is allowed.
4. Apply timeout and rate-limit settings.
5. Create an audit log record.

Current active-low-risk tools must stay fixed-size and timeout-bound, except cancellable multi-request tools such as `lab_bulk_route_exists_check`. Multi-request or long-running active tools must run through the in-process job registry, check the cancellation token between network requests, and write a cancelled audit record when stopped.

## Risk Levels

- `passive`: observes target responses without attack payloads.
- `active-low-risk`: sends safe lab payloads with strict limits.
- `active-high-risk`: requires explicit confirmation and an isolated lab profile.
