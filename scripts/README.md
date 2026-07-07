# Scripts

PowerShell helpers for operating the local lab.

## Commands

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-prereqs.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\start-lab.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\stop-lab.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\reset-lab.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\validate-lab.ps1
```

## Notes

- Scripts assume they are run from this repository.
- `start-lab.ps1` creates `.env` from `.env.example` when needed.
- Keep `.env` bind addresses on `127.0.0.1` by default.
