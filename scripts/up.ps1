[CmdletBinding()]
param(
    [string]$WslDistribution = "",
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$env:WSL_UTF8 = "1"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $projectRoot

function Resolve-WslDistro {
    param([string]$Requested)
    if ($Requested) {
        return $Requested
    }
    $raw = wsl -l -q 2>$null
    $distros = @($raw | ForEach-Object { ($_ -replace "`0", "").Trim() } | Where-Object { $_ -and $_ -notlike "docker-desktop*" })
    if ($distros -contains "Ubuntu-24.04") { return "Ubuntu-24.04" }
    if ($distros -contains "Ubuntu") { return "Ubuntu" }
    if ($distros.Count -gt 0) { return $distros[0] }
    throw "No Linux WSL2 distribution found. Install Ubuntu in WSL2 ('wsl --install -d Ubuntu-24.04')."
}

function Ensure-EnvFile {
    $envPath = Join-Path $projectRoot ".env"
    $examplePath = Join-Path $projectRoot ".env.example"
    if (-not (Test-Path $envPath)) {
        Write-Host "[1/6] Creating .env from .env.example with local lab defaults..."
        Copy-Item $examplePath $envPath -Force
    }
    $content = Get-Content $envPath -Raw
    if ($content -match "SOCLAB_WAZUH_PASSWORD=(CHANGE_ME|\s*$)") {
        $content = $content -replace "(?m)^SOCLAB_WAZUH_PASSWORD=.*$", "SOCLAB_WAZUH_PASSWORD=MyS3cr37P450r.*-"
    }
    if ($content -match "SOCLAB_WEBHOOK_TOKEN=(CHANGE_ME|\s*$)") {
        $content = $content -replace "(?m)^SOCLAB_WEBHOOK_TOKEN=.*$", "SOCLAB_WEBHOOK_TOKEN=soclab-dev-token"
    }
    Set-Content -Path $envPath -Value $content -NoNewline
}

function Ensure-PythonCli {
    $venvCli = Join-Path $projectRoot ".venv\Scripts\soclab.exe"
    if (Test-Path $venvCli) {
        return $venvCli
    }
    if (Get-Command uv -ErrorAction SilentlyContinue) {
        Write-Host "Installing Python environment via uv sync..."
        uv sync
        if (Test-Path $venvCli) {
            return $venvCli
        }
    }
    throw "Could not find .venv\Scripts\soclab.exe. Run 'uv sync' first."
}

function Wait-HttpReady {
    param(
        [string]$Name,
        [string]$Url,
        [int]$TimeoutSeconds = 180,
        [string]$PythonExe = (Join-Path $projectRoot ".venv\Scripts\python.exe")
    )
    Write-Host "Waiting for $Name ($Url)..."
    $probeScript = @'
import sys, httpx
try:
    response = httpx.get(sys.argv[1], verify=False, follow_redirects=True, timeout=4.0)
    response.raise_for_status()
except Exception:
    sys.exit(1)
'@
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $PythonExe) {
            $probeScript | & $PythonExe - $Url
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  $Name is ready."
                return
            }
        }
        else {
            try {
                $null = Invoke-WebRequest -Uri $Url -TimeoutSec 4 -UseBasicParsing -ErrorAction Stop
                Write-Host "  $Name is ready."
                return
            }
            catch {
            }
        }
        Start-Sleep -Seconds 3
    }
    throw "Timed out waiting for $Name at $Url"
}

Write-Host "=== Open SOC Lab - 1-Click Startup ==="
Ensure-EnvFile
$soclabExe = Ensure-PythonCli
$pythonExe = Join-Path $projectRoot ".venv\Scripts\python.exe"
$distro = Resolve-WslDistro -Requested $WslDistribution
Write-Host "Using WSL distribution: $distro"

# Clear empty gitlink directory if wazuh-docker has not been cloned yet.
$wazuhDir = Join-Path $projectRoot "infra\wazuh-docker"
$wazuhCompose = Join-Path $wazuhDir "single-node\docker-compose.yml"
if ((Test-Path $wazuhDir) -and (-not (Test-Path $wazuhCompose))) {
    Write-Host "[2/6] Removing empty infra/wazuh-docker placeholder..."
    Remove-Item -Recurse -Force $wazuhDir
}

Write-Host "[2/6] Starting Wazuh SIEM stack (Manager + Indexer + Dashboard)..."
& (Join-Path $PSScriptRoot "bootstrap_wazuh.ps1") -WslDistribution $distro

Write-Host "[3/6] Creating runtime directories..."
New-Item -ItemType Directory -Force -Path `
    (Join-Path $projectRoot "runtime\suricata"), `
    (Join-Path $projectRoot "runtime\shuffle-apps"), `
    (Join-Path $projectRoot "runtime\shuffle-files"), `
    (Join-Path $projectRoot "logs\evidence") | Out-Null

Write-Host "[4/6] Starting Stage 4 lab stack (Suricata + Linux Target + SOC Lab API + Shuffle + Mailpit + Kali)..."
if ($SkipBuild.IsPresent) {
    docker compose --profile full up -d
}
else {
    docker compose --profile full up -d --build
}

Write-Host "[5/6] Waiting for SOC Lab API, Wazuh Dashboard, Shuffle Backend, and Shuffle UI..."
Wait-HttpReady -Name "SOC Lab API" -Url "http://127.0.0.1:8080/health" -TimeoutSeconds 90 -PythonExe $pythonExe
Wait-HttpReady -Name "Wazuh Dashboard" -Url "https://127.0.0.1" -TimeoutSeconds 180 -PythonExe $pythonExe
Wait-HttpReady -Name "Shuffle Backend" -Url "http://127.0.0.1:5001/api/v1/health" -TimeoutSeconds 180 -PythonExe $pythonExe
Wait-HttpReady -Name "Shuffle UI" -Url "http://127.0.0.1:3001" -TimeoutSeconds 180 -PythonExe $pythonExe

Write-Host "[6/6] Provisioning Wazuh integration, custom rules, Shuffle workflow, and Dashboards..."
$provisionOk = $false
for ($attempt = 1; $attempt -le 6; $attempt++) {
    & $soclabExe lab provision
    if ($LASTEXITCODE -eq 0) {
        $provisionOk = $true
        break
    }
    Write-Host "Provisioning retry $attempt/6 (waiting for Shuffle apps to finish loading)..."
    Start-Sleep -Seconds 15
}
if (-not $provisionOk) {
    throw "Provisioning failed after retries."
}

& $soclabExe stage4 verify --quick

Write-Host ""
Write-Host "=== Open SOC Lab Ready ==="
Write-Host "Wazuh Dashboard : https://localhost   (admin / SecretPassword)"
Write-Host "Shuffle SOAR UI : http://localhost:3001 (admin / soclab-shuffle-admin)"
Write-Host "Mailpit Webmail : http://127.0.0.1:8025"
Write-Host "SOC Lab API Docs: http://127.0.0.1:8080/docs"
Write-Host "Linux Web Target: http://127.0.0.1:8081"
Write-Host ""
Write-Host "Next: simulate attacks from Kali container with:"
Write-Host "  .\.venv\Scripts\soclab.exe attack all"
Write-Host "  .\.venv\Scripts\soclab.exe attack check"
