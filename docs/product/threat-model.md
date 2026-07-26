# Product Threat Model

## Trust boundaries

```text
[Partner / CI / Operator UI]
        |
   Control plane (FastAPI /v1)  -- OIDC token validation, RBAC
        |
   Policy + tenant repos + PostgreSQL (RLS)
        |
   Scenario engine
        |
   Worker / synthetic agent adapter  -- capability document (Phase 2+)
        |
   Tool execution (existing safety: allowlist, policy, rate limit, audit)
        |
   Evidence store (PG metadata + MinIO/S3 blobs)
```

## Critical threats and mitigations

| Threat | Boundary | Mitigation (Product Core+) |
|---|---|---|
| Cross-tenant access | Control plane / DB | `organization_id` on all rows; app authz; PostgreSQL RLS; isolation tests |
| Confused-deputy tool invocation | Agent / tools | Scenario assertions on unauthorized tool calls; capability revalidation |
| Secret leakage | Worker / evidence | Redaction map in evidence manifest; no secrets in logs; namespaced object keys |
| Evidence tampering | Evidence store | Content hashes + sealed manifests; append-only authz audit |
| Policy bypass | Control plane / worker | Tool-level enforcement even when API validated; capability ceilings |
| Unsafe egress | Worker | Allowlist / network policy; lab-local only in Core |
| Runaway cost | Scenario / worker | Cost/time ceilings on runs; resource-exhaustion scenario |
| Cancellation failure | Jobs / worker | Cancel tokens; run states; cancel latency metrics |
| Dependency substitution | Supply chain | Pinned deps; SBOM in Enterprise; signed images later |

## Accepted risks (Product Core)

| Risk | Rationale | Expiry |
|---|---|---|
| In-process runs (no Temporal) | Sufficient for deterministic synthetic scenarios | Private Beta start |
| Evidence blobs not yet in object store | Metadata + inline redacted events enough for Core gate | Private Beta start |
| Local Keycloak / dev auth bypass for tests | Lab-only; production uses managed OIDC | Before external design partners |

## High-severity mitigations assigned

1. Cross-tenant isolation tests must stay green (owner: platform).
2. Every scenario run persists expected-vs-observed events before pass/fail (owner: scenario engine).
3. Authz denials write audit records (owner: control plane).
