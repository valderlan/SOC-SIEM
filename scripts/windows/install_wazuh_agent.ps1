[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Manager,

    [string]$AgentName = $env:COMPUTERNAME,

    [string]$Version = "4.14.8"
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
}

$msiName = "wazuh-agent-$Version-1.msi"
$msiPath = Join-Path $env:TEMP $msiName
$url = "https://packages.wazuh.com/4.x/windows/$msiName"

Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $msiPath -UseBasicParsing

$arguments = @(
    "/i", $msiPath,
    "/q",
    "WAZUH_MANAGER=$Manager",
    "WAZUH_REGISTRATION_SERVER=$Manager",
    "WAZUH_AGENT_NAME=$AgentName"
)

Write-Host "Installing Wazuh agent '$AgentName' -> $Manager"
$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru
if ($process.ExitCode -ne 0) {
    throw "Wazuh MSI installation failed with exit code $($process.ExitCode)."
}

Start-Service wazuhsvc
Set-Service wazuhsvc -StartupType Automatic

Get-Service wazuhsvc | Format-Table Status, Name, DisplayName -AutoSize
Write-Host "Wazuh agent installation completed."
