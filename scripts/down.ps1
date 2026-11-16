[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $projectRoot

Write-Host "Stopping Stage 4 Docker Compose stack..."
docker compose --profile full down
docker rm -f tenzir-node 2>$null | Out-Null

$wazuhStop = Join-Path $PSScriptRoot "wazuh_stop.ps1"
$wazuhSingleNode = Join-Path $projectRoot "infra\wazuh-docker\single-node"
if ((Test-Path $wazuhStop) -and (Test-Path $wazuhSingleNode)) {
    Write-Host "Stopping Wazuh single-node stack..."
    & $wazuhStop
}

Write-Host "Open SOC Lab stopped."
