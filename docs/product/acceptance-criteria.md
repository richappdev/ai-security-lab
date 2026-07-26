# Product Core Acceptance Criteria

## In scope (Days 0–30)

- Domain glossary, ownership rules, and product threat model published under `docs/product/`.
- PostgreSQL-backed tenant model with `organization_id` on every tenant-owned record.
- Application authorization + PostgreSQL RLS; denial-path and cross-org isolation tests.
- Local OIDC via Keycloak (Compose); RBAC roles: `owner`, `operator`, `viewer`.
- Normalized agent/tool event envelope and deterministic scenario contract.
- Evidence manifest schema (hashes, ownership, object refs); blob store deferred to MinIO in Beta.
- Synthetic agent adapter (vendor-neutral); no framework lock-in.
- At least five deterministic scenarios with stable pass/fail assertions.
- Two organizations can evaluate agents without crossing jobs, findings, secrets, traces, or evidence.
- Existing HTTP tools remain a target-adapter pack; no new scanner endpoints unless a reviewed scenario requires one.
- Agents never bypass policy or call targets directly; tool-level enforcement remains mandatory.

## Non-goals (Product Core)

- Temporal / disposable workers (Private Beta).
- MinIO/S3 blob evidence store (metadata only in Core).
- CI release-gate integrations (Private Beta).
- React/Next.js product UI rewrite (static/API-first is enough).
- SAML, SCIM, customer-managed keys, private worker pools (Enterprise).
- Custom authentication (managed OIDC only).
- Kafka, Elasticsearch, microservices, OPA/Rego, Redis-as-job-store.
- Credential stuffing, exploit automation, public targets, high-volume crawling.

## Exit gate checklist

- [x] Two orgs create projects and agents.
- [x] Both run deterministic evaluations.
- [x] Neither accesses the other’s jobs, findings, policies, secrets, traces, or evidence.
- [x] Critical authorization decisions are audited.
- [x] ≥5 scenarios have stable assertions and repeatable results.
- [x] Product threat model reviewed; high-severity mitigations assigned.
