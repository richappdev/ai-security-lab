# Safety Rules

This repository is for authorized local lab testing only.

## Allowed

- Testing OWASP Juice Shop on localhost.
- Testing DVWA on localhost.
- Passive HTTP inspection of allowlisted lab targets.
- Same-origin crawling of allowlisted lab targets.
- Low-rate active checks against local lab targets after guard checks pass.

## Blocked

- Testing public IPs, public websites, school systems, government systems, company systems, or unknown third-party assets.
- Denial-of-service, stress, or load testing.
- Credential stuffing or broad brute force.
- Destructive exploitation.
- Lateral movement.
- Exfiltration of real data.
- Any attempt to bypass `targets.allowlist`.

## Required Controls

- Allowlist enforcement before every network request.
- Localhost binding by default.
- Per-tool timeout.
- Per-tool rate limit.
- Audit logging for all tool calls.
- Clear report labeling by risk level.
- Job-registry stop/cancel support for any multi-request or long-running active tool.

## Human Review Required

Human review is required before:

- Adding a new active tool.
- Raising rate limits.
- Adding non-localhost targets.
- Enabling high-risk modules.
- Changing `safety/policy.yml`.
