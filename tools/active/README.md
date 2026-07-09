# Active Tools

Active tools send test inputs to allowlisted lab targets.

Use localhost URLs from host tools. Use `.local` target aliases when the containerized API is the component sending requests to the lab targets.

Requirements:

- Explicit listing in `tools/manifest.yml`.
- Human review before first use.
- Strict timeout and rate limit.
- Audit logging.
- Lab-only target enforcement.

Current active-low-risk tools are fixed-size checks where timeout is the stop boundary. Multi-request or long-running active tools require explicit stop/cancel support before implementation.

Implemented active-low-risk tools:

- `lab_xss_reflection_check`: single-request reflected-input marker check.
- `lab_http_methods_check`: single-request HTTP OPTIONS method check.
- `lab_route_exists_check`: single-request known-route existence check.
- `lab_security_header_delta_check`: fixed two-request security header comparison between root and one known route.
- `lab_auth_page_metadata_check`: single-request GET-only authentication page metadata check without credential submission.

High-risk tools should not be added until the safety layer is fully implemented and tested.
