# Entity Relationship Diagram (Product Core)

```mermaid
erDiagram
  Organization ||--o{ Membership : has
  Organization ||--o{ Project : owns
  Organization ||--o{ Policy : defines
  Organization ||--o{ Exception : grants
  Project ||--o{ Environment : contains
  Project ||--o{ Agent : registers
  Project ||--o{ Suite : owns
  Project ||--o{ Run : executes
  Project ||--o{ Finding : produces
  Project ||--o{ Evidence : seals
  Agent ||--o{ Model : pins
  Agent ||--o{ Tool : grants
  Agent ||--o{ McpServer : discovers
  Suite ||--o{ SuiteScenario : includes
  Scenario ||--o{ SuiteScenario : listed_in
  Run }o--|| Agent : targets
  Run }o--o| Suite : uses
  Run }o--o| Scenario : uses
  Run ||--o{ Finding : yields
  Run ||--o| Evidence : produces
  Finding }o--o| Approval : may_require
  Policy ||--o{ Exception : waived_by
```

## Tenancy key

All tenant-owned tables include `organization_id UUID NOT NULL`.
Project-scoped tables also include `project_id UUID NOT NULL`.
RLS policies enforce `organization_id = current_setting('app.organization_id')::uuid`.
