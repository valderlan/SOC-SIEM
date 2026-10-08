Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$singleNodeDir = Join-Path $projectRoot "infra/wazuh-docker/single-node"

if (-not (Test-Path -Path $singleNodeDir -PathType Container)) {
    throw "Wazuh single-node directory not found at: $singleNodeDir. Nothing to stop."
}

Push-Location $singleNodeDir
try {
    docker compose stop
}
finally {
    Pop-Location
}
