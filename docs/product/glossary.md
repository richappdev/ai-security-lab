# Domain Glossary — AI Agent Security Validation Platform

Primary customer: AI application/platform teams building agents.
Secondary buyer/reviewer: enterprise security teams.

## Entities

| Entity | Definition | Owned by |
|---|---|---|
| **Organization** | Tenant boundary for all product data. Isolation root for RLS. | Platform (created at signup) |
| **Membership** | User ↔ Organization link with org-level role. | Organization |
| **Project** | Workstream within an org (e.g. one agent product line). | Organization |
| **Environment** | Deployment context within a project (`dev`, `staging`, `prod`). | Project |
| **Agent** | Registered agent under test: identity, version, tool grants, model pins. | Project |
| **Model** | Model provider/version pin referenced by an Agent. | Project (or org catalog) |
| **Tool** | Named capability an Agent may invoke (HTTP adapter, MCP tool, etc.). | Project |
| **MCP Server** | Registered MCP endpoint an Agent may discover tools from. | Project |
| **Scenario** | Versioned deterministic evaluation: fixtures, expected events, assertions. | Organization (or platform catalog) |
| **Suite** | Ordered/grouped set of Scenarios used as a release gate. | Project |
| **Run** | Single execution of a Scenario or Suite against an Agent version. | Project |
| **Finding** | Structured failure or risk result produced by a Run. | Project |
| **Evidence** | Manifest + hashes + object refs proving Run inputs/outputs. | Project |
| **Policy** | Release or runtime rule (thresholds, allowed tools, approval needs). | Organization / Project |
| **Approval** | Recorded human decision for a high-impact action or exception. | Project |
| **Exception** | Time-bounded, documented waiver of a Policy requirement. | Organization |

## Lifecycle states

| Entity | States |
|---|---|
| Organization | `active`, `suspended`, `deleted` |
| Project | `active`, `archived` |
| Agent | `draft`, `registered`, `deprecated` |
| Scenario | `draft`, `published`, `retired` |
| Suite | `draft`, `active`, `retired` |
| Run | `queued`, `running`, `completed`, `failed`, `cancel_requested`, `cancelled` |
| Finding | `open`, `assigned`, `suppressed`, `accepted`, `remediated`, `verified` |
| Evidence | `pending`, `sealed`, `expired`, `purged` |
| Exception | `requested`, `approved`, `denied`, `expired`, `revoked` |
| Approval | `pending`, `approved`, `rejected`, `expired` |

## Ownership rules

1. Every tenant-owned row carries `organization_id`.
2. Project-scoped entities also carry `project_id` and inherit org isolation.
3. Cross-organization reads/writes are denied by application authz **and** PostgreSQL RLS.
4. Platform-catalog scenarios may be read by all orgs but never mutated by tenants.
5. Secrets and capability documents are never shared across organizations.
6. Evidence object keys are namespaced by `organization_id` / `project_id` / `run_id`.

## Release-gate workflow

```text
register Agent → attach Suite → create Run
  → fail (Finding + Evidence) → remediate Agent/Policy
  → identical Suite rerun → pass → export sealed Evidence bundle
```
