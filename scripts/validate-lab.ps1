$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$targets = @(
    @{ Name = "Juice Shop"; Url = "http://127.0.0.1:3000" },
    @{ Name = "DVWA"; Url = "http://127.0.0.1:8080" }
)

function Test-HttpTarget {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [string] $Url
    )

    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10
        Write-Host "$Name reachable at $Url (HTTP $($response.StatusCode))."
    }
    catch {
        throw "$Name is not reachable at $Url. Start the lab with scripts/start-lab.ps1 and try again."
    }
}

if (-not (Test-Path "targets.allowlist")) {
    throw "targets.allowlist is missing."
}

$allowlist = Get-Content "targets.allowlist" |
    Where-Object { $_ -and -not $_.TrimStart().StartsWith("#") } |
    ForEach-Object { $_.Trim() }

foreach ($target in $targets) {
    if ($allowlist -notcontains $target.Url) {
        throw "$($target.Url) is missing from targets.allowlist."
    }

    Test-HttpTarget -Name $target.Name -Url $target.Url
}

Write-Host "Lab validation completed."
