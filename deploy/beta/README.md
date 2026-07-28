# Partner Beta Certification

This directory contains the machine-readable inputs for promoting a deployment
from implementation-complete to partner-ready.

## Certification commands

Run the static, fail-closed configuration gate:

```powershell
python -m certification.readiness --profile beta
```

Run the PostgreSQL migration and RLS suite entirely inside disposable Docker
services:

```powershell
docker compose --profile test up `
  --build `
  --abort-on-container-exit `
  --exit-code-from postgres-test `
  postgres-test
docker compose --profile test rm --stop --force postgres-test postgres-test-db
```

The test database uses a container-local `tmpfs`; it does not mount or modify
the development PostgreSQL volume. Cleanup targets only the two test services,
so existing lab services remain running.

Probe PostgreSQL/Alembic/RLS, OIDC discovery and JWKS, Temporal Cloud, S3 bucket
versioning/encryption, the API contract, and the operations endpoint:

```powershell
python -m certification.readiness `
  --profile beta `
  --live `
  --base-url $env:BETA_BASE_URL `
  --output readiness.json
```

Run the permanent commercial exit workflow:

```powershell
python -m certification.beta_exit `
  --provider $env:CI_INTEGRATION_PROVIDER `
  --output beta-exit.json
```

For CI publishing, `BETA_ORGANIZATION_ID` must identify the organization that
owns `CI_INTEGRATION_INSTALLATION_ID`; the access token must have owner access
to that organization.

The workflow creates an isolated certification tenant and then:

1. Registers an insecure agent version and immutable suite revision.
2. Ingests a deterministic failing trace through a run capability.
3. Replays the batch to verify idempotency.
4. Confirms cross-tenant access is denied.
5. Confirms the release policy and CI payload block the build.
6. Records structured remediation and creates a new agent version.
7. Runs the unchanged suite revision and passes.
8. Verifies redaction and the signed export offline.
9. Confirms cancellation completes in less than ten seconds.
10. When configured, confirms both failure and success are published to CI.

Use the protected `Partner Beta Certification` GitHub Actions workflow to
execute both commands against a deployed environment. Store all credentials in
the `partner-beta` GitHub environment, require reviewer approval, and never
enter secrets as workflow inputs.

## Rollout scorecard

Copy `pilot-metrics.example.json`, replace the observations, and evaluate it:

```powershell
python -m certification.scorecard pilot-metrics.json --output scorecard.json
```

A deployment is not eligible for additional design partners unless every
machine-enforced gate passes. Product metrics are collected for decisions but
do not currently block promotion.
