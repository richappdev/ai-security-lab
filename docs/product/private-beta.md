# Private Beta engineering notes

Implemented beta control plane:

- **OIDC:** standards-compliant discovery/JWKS validation; local Keycloak remains available. Development header authentication is rejected by the beta startup profile.
- **Durable runs:** Temporal Cloud workflow definitions, event-driven evaluation runs, ordered/idempotent batches, cancellation, deadlines, and a local compatibility engine guarded by `ALLOW_LEGACY_SYNC_RUNS`.
- **Isolation:** Alembic-managed PostgreSQL RLS with `USING` and `WITH CHECK`, run-scoped capabilities, and a disposable non-root Docker launcher with default-deny egress.
- **Evidence:** recursive redaction, Ed25519 signing with key IDs, SHA-256 metadata, 30-day expiry, auditable purge, and JSON/SARIF/HTML/PDF export.
- **Product workflow:** immutable agent/suite/policy revisions, persisted suite runs, regression comparison, structured finding transitions, and expiring exceptions.
- **CI gates:** encrypted organization-scoped GitHub/GitLab installations; global tokens are local-compatibility only.
- **Operations:** correlation IDs, OpenTelemetry bootstrap, request metrics, beta configuration checks, and documented deployment/recovery procedures.

Exit gate: a design partner fails a build, inspects evidence, remediates, reruns the identical suite revision, passes, and exports an independently verifiable bundle.

See [Private Beta Operations](private-beta-operations.md).
