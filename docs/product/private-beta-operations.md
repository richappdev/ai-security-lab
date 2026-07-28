# Private Beta Operations

## Deployment invariants

- Set `DEPLOYMENT_ENV=beta`, `ALLOW_DEV_AUTH=false`, and `ALLOW_LEGACY_SYNC_RUNS=false`.
- Use PostgreSQL with Alembic at `head`; do not use `Base.metadata.create_all` as a deployment migration.
- Configure a standards-compliant OIDC issuer, Temporal Cloud, S3-compatible storage, separate Ed25519 evidence/capability keys, and a Fernet integration-encryption key.
- Run the FastAPI modular monolith and `python -m workers.main` as separate services.
- Permit worker egress only through reviewed per-run networks. The default Docker launcher uses `--network none`.

Application startup refuses beta or production mode when a required safety setting is absent.

## Deployment and rollback

1. Back up PostgreSQL and enable bucket versioning.
2. Run `python -m alembic upgrade head`.
3. Deploy the worker, then the API; verify `/health` and `/v1/operations/metrics`.
4. Run the event-ingestion smoke and one secure deterministic suite.
5. Roll back containers first. A database downgrade requires an explicit backup and review.

## Backup and restore

- Take daily PostgreSQL logical backups; retain 14 daily and 8 weekly copies.
- Enable S3 versioning and server-side encryption.
- Quarterly, restore into an isolated environment, recover one tenant/run prefix, verify hashes and the Ed25519 signature, and confirm RLS hides it from another tenant.
- Record the restore point, duration, operator, verification, and cleanup.

## Signing-key rotation

1. Generate a new Ed25519 key outside the repository.
2. Assign a new `EVIDENCE_SIGNING_KEY_ID`; retain prior public keys for verification.
3. Deploy workers and API with the new key.
4. Seal a canary run and verify it offline.
5. Never rewrite historical signatures. Revoke compromised keys and flag affected evidence.

Verify an exported JSON bundle with `python -m evidence.verify_cli path/to/evidence-bundle.json`.

## Incident response

- Disable affected integrations, revoke capabilities, cancel workflows, and terminate workers.
- Preserve audit rows, Temporal histories, object versions, traces, and signing-key IDs.
- Identify impacted organizations without exposing other tenants' identifiers or evidence.
- Rotate affected credentials and keys.
- Re-run isolation, redaction, recovery, and tamper tests before reopening execution.

## Partner offboarding

1. Disable memberships and installations.
2. Revoke capabilities and cancel workflows.
3. Export the agreed evidence package.
4. Apply the contractual retention window and run the auditable purge job.
5. Confirm PostgreSQL metadata and objects are purged or retained as agreed.

## Rollout gates

1. **Internal dogfood:** automated tests, PostgreSQL RLS, recovery, and seeded-secret tests pass.
2. **One non-critical project:** no isolation or redaction defect; cancellation p95 below 10 seconds.
3. **3–5 partners:** at least 95% deterministic reproducibility, complete evidence for every gate, and successful fail/remediate/rerun/pass workflows.

## Alerts

- Excess queue latency, run duration, or cancellation latency.
- Worker heartbeat loss, retry exhaustion, or recovery failure.
- Any seeded-secret rejection, evidence hash mismatch, or invalid signature.
- Policy bypass, authorization denial spike, or integration publish failure.
- Evidence purge or backup/restore verification failure.
