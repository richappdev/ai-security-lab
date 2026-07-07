$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

function Invoke-Docker {
    & docker @args
    if ($LASTEXITCODE -ne 0) {
        throw "Docker command failed: docker $args"
    }
}

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example."
}

Invoke-Docker compose up -d
Invoke-Docker compose ps

Write-Host ""
Write-Host "Juice Shop: http://127.0.0.1:3000"
Write-Host "DVWA:       http://127.0.0.1:8080"
