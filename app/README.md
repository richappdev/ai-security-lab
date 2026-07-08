# App

Local security app code goes here.

The planned MVP is a small local app that:

- Loads `targets.allowlist`.
- Uses the safety layer before tool execution.
- Runs passive tools first.
- Stores audit logs.
- Generates reports under `reports/`.

## API

The initial FastAPI app exposes:

- `GET /health`
- `POST /scan/passive/headers`
- `POST /scan/active/xss-reflection`
- `POST /scan/active/http-methods`

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
