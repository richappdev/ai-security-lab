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
- `POST /scan/passive/cookies`
- `POST /scan/passive/forms`
- `POST /scan/active/xss-reflection`
- `POST /scan/active/http-methods`
- `POST /scan/active/route-exists`
- `POST /scan/active/security-header-delta`
- `POST /scan/active/auth-page-metadata`
- `POST /scan/active/bulk-route-exists` (returns `job_id`)
- `GET /jobs/{job_id}`
- `POST /jobs/{job_id}/cancel`

Fixed-size active endpoints remain synchronous and timeout-bound. The bulk known-route exists endpoint is the first cancellable multi-request scan: it uses the in-process job registry, checks a cancellation token between HEAD requests, and is operated from `/ui/jobs.html`.

When calling the API from the host, use localhost for the API URL. In the JSON `target`, use `.local` aliases because the API container makes the target request from inside the Docker network. For host-side tools that contact targets directly, use `http://127.0.0.1:3000`, `http://localhost:3000`, `http://127.0.0.1:8080`, or `http://localhost:8080`.

Passive header example:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/scan/passive/headers `
  -ContentType application/json `
  -Body '{"target":"http://juice-shop.local:3000","operator":"local-user"}'
```

Passive cookie example:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/scan/passive/cookies `
  -ContentType application/json `
  -Body '{"target":"http://juice-shop.local:3000","operator":"local-user"}'
```

Passive form discovery example:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/scan/passive/forms `
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

Active bulk known-route exists example (async job):

```powershell
$job = Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/scan/active/bulk-route-exists `
  -ContentType application/json `
  -Body '{"target":"http://juice-shop.local:3000","operator":"local-user","rate_limit_per_minute":30}'
Invoke-RestMethod -Uri "http://127.0.0.1:8000/jobs/$($job.job_id)"
# Optional cancel:
# Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/jobs/$($job.job_id)/cancel"
```
