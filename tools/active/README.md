# Active Tools

Active tools send test inputs to allowlisted lab targets.

Requirements:

- Explicit listing in `tools/manifest.yml`.
- Human review before first use.
- Strict timeout and rate limit.
- Audit logging.
- Lab-only target enforcement.

High-risk tools should not be added until the safety layer is fully implemented and tested.
