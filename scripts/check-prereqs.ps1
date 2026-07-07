$ErrorActionPreference = "Stop"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker was not found. Install Docker Desktop, then reopen PowerShell."
}

docker compose version | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker Compose is not available."
}

Write-Host "Docker and Docker Compose are available."
