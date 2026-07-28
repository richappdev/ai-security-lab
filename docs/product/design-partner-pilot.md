# Design Partner Pilot

## Promotion sequence

1. **Internal dogfood**
   - The normal CI workflow, Docker beta-exit workflow, PostgreSQL RLS job, and
     Temporal test environment pass.
   - `certification.readiness --live` passes against the managed staging stack.
   - Complete the worker-loss, database restart, object-store interruption,
     signing-key rotation, backup/restore, and seeded-secret drills below.
2. **One non-critical project**
   - Run only the generic normalized event API.
   - Use one immutable suite revision for the full fail/remediate/pass cycle.
   - Review every false positive and every result divergence.
3. **Three to five partners**
   - Promote only after the first project produces a passing scorecard.
   - Add an SDK/framework adapter only when measured onboarding friction
     establishes its priority.

## Partner onboarding

- Identify the partner owner, security reviewer, project, repository, OIDC
  groups, data classification, allowed targets, and approved egress.
- Create an organization-scoped CI installation; never use a global token.
- Agree on evidence retention and offboarding dates.
- Seed synthetic credentials that are unique to the partner test environment.
- Register an agent version with prompt, model, tool, and dataset versions.
- Create and approve the initial immutable suite and release policy.
- Run the certification workflow before allowing the first release decision.

## Dogfood fault drills

Run these only in the isolated staging environment and record timestamps,
operators, affected run IDs, recovery time, and evidence object counts.

| Drill | Injection | Pass condition |
|---|---|---|
| Worker loss | Terminate one disposable worker during an active run | Temporal retries/recovery complete without duplicate findings or evidence |
| API restart | Restart the control plane after accepting an event batch | The same batch replays idempotently and the run remains resumable |
| PostgreSQL restart | Restart managed PostgreSQL during a queued run | API recovers, RLS remains active, and no cross-tenant data is returned |
| Object-store interruption | Deny S3 writes during sealing, then restore access | Run does not report success without evidence; sealing retries exactly once |
| Cancellation | Cancel ten active runs | p95 is below 10 seconds and workers terminate |
| Signing rotation | Rotate to a new key ID between two canary runs | Both bundles verify with the correct retained public key |
| Backup/restore | Restore one tenant/run prefix into isolation | Hashes/signatures verify and another tenant cannot read it |
| Secret seeding | Place unique secrets in every event location | No secret appears in PostgreSQL, objects, logs, traces, exports, or CI payloads |

## Weekly measurements

Record the machine gates in `deploy/beta/pilot-metrics.example.json` plus:

- Time to first useful evaluation
- Median release-validation duration
- Mean remediation time
- Percentage of runs used for a release decision
- False-positive rate and investigated divergences
- Cost per completed evaluation

Run `python -m certification.scorecard <metrics.json>` before each rollout
decision. Attach the readiness, beta-exit, scorecard, restore, and fault-drill
reports to the decision record.

## Stop conditions

Pause partner workloads immediately for any tenant-isolation defect, secret
leak, invalid signature, evidence-completeness defect, policy bypass, or
unrecoverable workflow. Follow the incident response procedure in
`private-beta-operations.md` before reopening execution.
