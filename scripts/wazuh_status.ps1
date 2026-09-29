param(
    [switch]$Logs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$singleNodeDir = Join-Path $projectRoot "infra/wazuh-docker/single-node"

if (-not (Test-Path -Path $singleNodeDir -PathType Container)) {
    throw "Wazuh single-node directory not found at: $singleNodeDir. Run scripts/bootstrap_wazuh.ps1 first."
}

Push-Location $singleNodeDir
try {
    docker compose ps
    if ($Logs.IsPresent) {
        Write-Host ""
        Write-Host "Showing last 100 log lines..."
        docker compose logs --tail 100
    }
}
finally {
    Pop-Location
}
