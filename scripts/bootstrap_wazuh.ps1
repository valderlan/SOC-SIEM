param(
    [string]$WazuhVersion = "v4.14.8",
    [string]$WslDistribution = "Ubuntu"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-CommandExists {
    param([Parameter(Mandatory = $true)][string]$Name)

    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found in PATH."
    }
}

function Test-Docker {
    Write-Host "Checking Docker CLI and daemon..."
    try {
        $null = docker version 2>$null
    }
    catch {
        throw "Docker daemon is unavailable. Start Docker Desktop and try again."
    }

    try {
        $null = docker compose version 2>$null
    }
    catch {
        throw "Docker Compose v2 is unavailable. Verify Docker Desktop installation."
    }
}

function Test-WslDistribution {
    param([Parameter(Mandatory = $true)][string]$Distribution)

    Write-Host "Checking WSL distribution '$Distribution'..."
    $raw = wsl -l -q
    $available = @($raw | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($available -notcontains $Distribution) {
        $list = if ($available.Count -gt 0) { $available -join ", " } else { "(none)" }
        throw "WSL distribution '$Distribution' was not found. Available distributions: $list"
    }
}

function Set-WazuhKernelRequirements {
    param([Parameter(Mandatory = $true)][string]$Distribution)

    Write-Host "Configuring vm.max_map_count in WSL..."
    wsl -d $Distribution -u root -- sysctl -w vm.max_map_count=262144 | Out-Null
    $current = (wsl -d $Distribution -- sh -lc "sysctl -n vm.max_map_count").Trim()
    if (-not $current) {
        throw "Could not verify vm.max_map_count value in WSL."
    }
    if ([int]$current -lt 262144) {
        throw "vm.max_map_count is $current in WSL, but Wazuh requires at least 262144."
    }
    Write-Host "vm.max_map_count is $current"
}

function Install-WazuhDocker {
    param(
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$ProjectRoot
    )

    $infraDir = Join-Path $ProjectRoot "infra"
    $repoDir = Join-Path $infraDir "wazuh-docker"

    if (-not (Test-Path -Path $infraDir -PathType Container)) {
        New-Item -Path $infraDir -ItemType Directory | Out-Null
    }

    if (-not (Test-Path -Path $repoDir -PathType Container)) {
        Write-Host "Cloning wazuh-docker $Version into infra/wazuh-docker..."
        git clone --depth 1 --branch $Version https://github.com/wazuh/wazuh-docker.git $repoDir
    }
    else {
        Write-Host "Reusing existing infra/wazuh-docker checkout."
        $gitDir = Join-Path $repoDir ".git"
        $singleNode = Join-Path $repoDir "single-node"
        $composeFile = Join-Path $singleNode "docker-compose.yml"
        if (-not (Test-Path -Path $gitDir) -or -not (Test-Path -Path $composeFile)) {
            throw "Existing infra/wazuh-docker does not look like a valid wazuh-docker checkout."
        }
    }

    return $repoDir
}

function New-WazuhCertificates {
    param([Parameter(Mandatory = $true)][string]$SingleNodeDir)

    $rootCa = Join-Path $SingleNodeDir "config/wazuh_indexer_ssl_certs/root-ca.pem"
    if (Test-Path -Path $rootCa -PathType Leaf) {
        Write-Host "Indexer certificates already exist. Skipping generation."
        return
    }

    Write-Host "Generating indexer certificates..."
    docker compose -f generate-indexer-certs.yml run --rm generator
}

function Start-Wazuh {
    param([Parameter(Mandatory = $true)][string]$SingleNodeDir)

    Push-Location $SingleNodeDir
    try {
        Write-Host "Validating Docker Compose configuration..."
        docker compose config | Out-Null

        New-WazuhCertificates -SingleNodeDir $SingleNodeDir

        Write-Host "Starting Wazuh single-node stack..."
        docker compose up -d
    }
    finally {
        Pop-Location
    }
}

function Show-WazuhStatus {
    param([Parameter(Mandatory = $true)][string]$SingleNodeDir)

    Push-Location $SingleNodeDir
    try {
        docker compose ps
    }
    finally {
        Pop-Location
    }

    Write-Host ""
    Write-Host "Dashboard:"
    Write-Host "https://localhost"
    Write-Host ""
    Write-Host "Default dashboard credentials for Wazuh Docker v4.14.8:"
    Write-Host "username: admin"
    Write-Host "password: SecretPassword"
    Write-Host ""
    Write-Host "Wazuh API for this project:"
    Write-Host "https://127.0.0.1:55000"
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Write-Host "Project root: $projectRoot"
Test-CommandExists -Name "git"
Test-CommandExists -Name "docker"
Test-CommandExists -Name "wsl"

Test-Docker
Test-WslDistribution -Distribution $WslDistribution
Set-WazuhKernelRequirements -Distribution $WslDistribution

$wazuhRepoDir = Install-WazuhDocker -Version $WazuhVersion -ProjectRoot $projectRoot
$singleNodeDir = Join-Path $wazuhRepoDir "single-node"

$requiredPaths = @(
    (Join-Path $singleNodeDir "docker-compose.yml"),
    (Join-Path $singleNodeDir "generate-indexer-certs.yml"),
    (Join-Path $singleNodeDir "config")
)

foreach ($requiredPath in $requiredPaths) {
    if (-not (Test-Path -Path $requiredPath)) {
        throw "Required path is missing: $requiredPath"
    }
}

Start-Wazuh -SingleNodeDir $singleNodeDir
Show-WazuhStatus -SingleNodeDir $singleNodeDir
