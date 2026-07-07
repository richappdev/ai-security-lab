$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

& docker compose down
if ($LASTEXITCODE -ne 0) {
    throw "Docker command failed: docker compose down"
}
