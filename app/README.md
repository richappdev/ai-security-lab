# App

Local security app code lives here.

The current MVP is a small local app that:

- Loads `targets.allowlist`.
- Uses the safety layer before tool execution.
- Runs passive tools first.
- Stores audit logs.
- Generates reports under `reports/`.

## API

The FastAPI app exposes:

- `GET /health`
- `POST /scan/passive/headers`
- `POST /scan/active/xss-reflection`
- `POST /scan/active/http-methods`
- `POST /scan/active/route-exists`
- `POST /scan/active/security-header-delta`
- `POST /scan/active/auth-page-metadata`
- `GET /jobs/{job_id}`
- `POST /jobs/{job_id}/cancel`

The current active endpoints run fixed-size, low-risk checks. They are bounded by allowlist validation, policy-backed timeout and rate-limit settings, and audit logging. Future multi-request or long-running active scans must use the in-process job registry and cancellation token before they are added.

When calling the API from the host, use localhost for the API URL. In the JSON `target`, use `.local` aliases because the API container makes the target request from inside the Docker network. For host-side tools that contact targets directly, use `http://127.0.0.1:3000`, `http://localhost:3000`, `http://127.0.0.1:8080`, or `http://localhost:8080`.

Passive header example:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/scan/passive/headers `
  -ContentType application/json `
  -Body '{"target":"http://juice-shop.local:3000","operator":"local-user"}'
```

Active HTTP methods example:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/scan/active/http-methods `
  -ContentType application/json `
  -Body '{"target":"http://juice-shop.local:3000","operator":"local-user","rate_limit_per_minute":30}'
```

Active route existence example:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/scan/active/route-exists `
  -ContentType application/json `
  -Body '{"target":"http://juice-shop.local:3000","route_path":"/login","operator":"local-user","rate_limit_per_minute":30}'
```

Active security header delta example:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/scan/active/security-header-delta `
  -ContentType application/json `
  -Body '{"target":"http://juice-shop.local:3000","route_path":"/login","operator":"local-user","rate_limit_per_minute":30}'
```

Active auth page metadata example:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/scan/active/auth-page-metadata `
  -ContentType application/json `
  -Body '{"target":"http://juice-shop.local:3000","route_path":"/login","operator":"local-user","rate_limit_per_minute":30}'
```
