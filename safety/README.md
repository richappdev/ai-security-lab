# Safety

This directory is for policy and guard code used by agents and tools.

Current modules:

- `scope_guard.py`: load `targets.allowlist`, normalize URLs, and reject out-of-scope targets before network access.
- `audit_log.py`: write append-only structured JSONL audit records.

Planned modules:

- `rate_limit.py`: constrain request volume.
- `policy.py`: load and enforce `safety/policy.yml`.

No active tool should run until the relevant safety guard exists and is tested.
