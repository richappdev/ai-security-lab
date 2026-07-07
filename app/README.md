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

Example:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/scan/passive/headers `
  -ContentType application/json `
  -Body '{"target":"http://juice-shop.local:3000","operator":"local-user"}'
```
