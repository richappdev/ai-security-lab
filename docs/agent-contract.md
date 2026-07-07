# Agent Contract

This contract describes how an AI agent should behave in this repository.

## Responsibilities

- Read repository instructions before acting.
- Treat `targets.allowlist` as the source of truth for allowed targets.
- Prefer passive checks before active checks.
- Select tools from `tools/manifest.yml`.
- Explain the planned action before running active checks.
- Preserve auditability by logging target, tool, start time, end time, result, and operator.

## Required Inputs

An agent plan should include:

- `target`: URL to test.
- `objective`: what the operator wants to learn.
- `risk_level`: one of `passive`, `active-low-risk`, or `active-high-risk`.
- `tools`: list of tool names from `tools/manifest.yml`.
- `limits`: timeout and request-rate settings.

## Required Checks

Before requesting a tool run, the agent must confirm:

- The target appears in `targets.allowlist`.
- The activity is allowed by `safety/policy.yml`.
- The chosen tool risk level is appropriate for the objective.
- The tool has a timeout.
- The tool has audit logging enabled.

## Prohibited Behavior

The agent must not:

- Invent target authorization.
- Test public or third-party systems.
- Bypass allowlist checks.
- Run destructive exploit code.
- Run denial-of-service or stress tests.
- Perform credential stuffing.
- Continue after a safety guard rejects a request.
