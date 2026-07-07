# Safety

This directory is for policy and guard code used by agents and tools.

Planned modules:

- `allowlist.py`: load and normalize approved targets.
- `scope_guard.py`: reject out-of-scope targets before network access.
- `rate_limit.py`: constrain request volume.
- `audit_log.py`: write structured audit records.
- `policy.py`: load and enforce `safety/policy.yml`.

No active tool should run until the relevant safety guard exists and is tested.
