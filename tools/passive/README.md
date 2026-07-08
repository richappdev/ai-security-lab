# Passive Tools

Passive tools observe responses from allowlisted lab targets without exploit payloads.

Examples:

- Header inspection
- Cookie inspection
- Link discovery
- Form discovery without submission
- Basic technology hints

Implemented:

- `headers.py`: `inspect_headers`, a passive allowlist-guarded response header check with JSONL audit logging.
- `cookies.py`: `inspect_cookies`, a passive allowlist-guarded cookie attribute check with JSONL audit logging.
