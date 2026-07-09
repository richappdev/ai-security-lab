# Active Tools

Active tools send test inputs to allowlisted lab targets.

Use localhost URLs from host tools. Use `.local` target aliases when the containerized API is the component sending requests to the lab targets.

Requirements:

- Explicit listing in `tools/manifest.yml`.
- Human review before first use.
- Strict timeout and rate limit.
- Audit logging.
- Lab-only target enforcement.

Current active-low-risk tools are single-request checks where timeout is the stop boundary. Multi-request or long-running active tools require explicit stop/cancel support before implementation.

High-risk tools should not be added until the safety layer is fully implemented and tested.
