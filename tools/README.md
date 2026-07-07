# Tools

Tools are the only components that may interact with lab targets.

Each tool must:

- Be listed in `tools/manifest.yml`.
- Validate target scope before network access.
- Respect `safety/policy.yml`.
- Use timeouts and rate limits.
- Write audit logs.
- Return structured results.

Passive tools belong in `tools/passive/`.

Active tools belong in `tools/active/` and require stricter review.

External scanner integrations belong in `tools/adapters/`.
