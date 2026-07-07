$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

function Invoke-Docker {
    & docker @args
    if ($LASTEXITCODE -ne 0) {
        throw "Docker command failed: docker $args"
    }
}

Invoke-Docker compose down --volumes
Invoke-Docker compose up -d
Invoke-Docker compose ps
