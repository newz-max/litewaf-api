param(
    [Parameter(Mandatory = $true)]
    [string]$HostName,
    [int]$Port = 22,
    [string]$RemoteBase = "/opt/litewaf",
    [string]$ProjectName = "litewaf",
    [string]$IdentityFile = "",
    [int]$KeepReleases = 3,
    [string]$ComposeFileName = "docker-compose.prod.yml"
)

$ErrorActionPreference = "Stop"

function Require-Command {
    param([string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

function Assert-NoSingleQuote {
    param(
        [string]$Name,
        [string]$Value
    )

    if ($Value -match "'") {
        throw "$Name must not contain a single quote: $Value"
    }
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
}

function Format-HttpUrl {
    param(
        [string]$HostValue,
        [string]$PortValue
    )

    if ($PortValue -eq "80") {
        return "http://${HostValue}"
    }
    return "http://${HostValue}:$PortValue"
}

function Format-GatewayListenerInfo {
    param(
        [hashtable]$Values
    )

    $Mode = if ($Values.ContainsKey("GATEWAY_LISTENER_MODE")) { $Values["GATEWAY_LISTENER_MODE"] } else { "host-network" }
    $Range = if ($Values.ContainsKey("GATEWAY_BRIDGE_PORT_RANGE")) { $Values["GATEWAY_BRIDGE_PORT_RANGE"] } else { "" }
    if ($Mode -eq "bridge-range" -and $Range) {
        return "Gateway listeners: bridge-range $Range"
    }
    return "Gateway listeners: $Mode"
}

Require-Command ssh
Require-Command scp
Require-Command tar

Assert-NoSingleQuote -Name "RemoteBase" -Value $RemoteBase
Assert-NoSingleQuote -Name "ProjectName" -Value $ProjectName
Assert-NoSingleQuote -Name "ComposeFileName" -Value $ComposeFileName

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
$DeployDir = Join-Path $ProjectRoot "deploy"
$ComposeFile = Join-Path $DeployDir $ComposeFileName
$EnvExample = Join-Path $DeployDir ".env.example"
$CtlScript = Join-Path $DeployDir "litewafctl.sh"

foreach ($Path in @($ComposeFile, $EnvExample, $CtlScript)) {
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Required deployment file not found: $Path"
    }
}

$TimeStamp = Get-Date -Format "yyyyMMddHHmmss"
$ArchiveName = "litewaf-deploy-$TimeStamp.tar.gz"
$ArchivePath = Join-Path ([System.IO.Path]::GetTempPath()) $ArchiveName
$RemoteArchive = "/tmp/$ArchiveName"
$RemoteRelease = "$RemoteBase/releases/$TimeStamp"
$RemoteCurrent = "$RemoteBase/current"
$RemoteShared = "$RemoteBase/shared"

$SshArgs = @()
$ScpArgs = @()

if ($Port -ne 22) {
    $SshArgs += @("-p", "$Port")
    $ScpArgs += @("-P", "$Port")
}

if ($IdentityFile) {
    $SshArgs += @("-i", $IdentityFile)
    $ScpArgs += @("-i", $IdentityFile)
}

$SshArgs += @(
    "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=3",
    $HostName
)

$ScpTarget = "${HostName}:$RemoteArchive"
$DisplayHost = ($HostName -split "@")[-1]

Write-Host "==> Checking remote Docker runtime..."
Invoke-Native ssh @SshArgs @"
set -euo pipefail
docker --version
docker compose version
df -h '$RemoteBase' 2>/dev/null || df -h /
ulimit -n
"@

Write-Host "==> Creating deployment archive: $ArchivePath"
if (Test-Path -LiteralPath $ArchivePath) {
    Remove-Item -LiteralPath $ArchivePath -Force
}

$TarArgs = @(
    "-czf", $ArchivePath,
    "-C", $DeployDir,
    $ComposeFileName,
    ".env.example",
    "litewafctl.sh"
)

Invoke-Native tar @TarArgs

Write-Host "==> Uploading archive to $HostName..."
Invoke-Native scp @ScpArgs $ArchivePath $ScpTarget

$RemoteScript = @"
set -euo pipefail

REMOTE_BASE='$RemoteBase'
REMOTE_ARCHIVE='$RemoteArchive'
REMOTE_RELEASE='$RemoteRelease'
REMOTE_CURRENT='$RemoteCurrent'
REMOTE_SHARED='$RemoteShared'
PROJECT_NAME='$ProjectName'
KEEP_RELEASES='$KeepReleases'
COMPOSE_FILE_NAME='$ComposeFileName'

mkdir -p "`$REMOTE_RELEASE" "`$REMOTE_SHARED"
tar -xzf "`$REMOTE_ARCHIVE" -C "`$REMOTE_RELEASE"

if [ ! -f "`$REMOTE_SHARED/.env" ]; then
  cp "`$REMOTE_RELEASE/.env.example" "`$REMOTE_SHARED/.env"
fi

cp "`$REMOTE_SHARED/.env" "`$REMOTE_RELEASE/.env"

cd "`$REMOTE_RELEASE"
chmod +x ./litewafctl.sh 2>/dev/null || true
PROJECT_NAME="`$PROJECT_NAME" COMPOSE_FILE="`$COMPOSE_FILE_NAME" ENV_FILE=.env ./litewafctl.sh install
cp "`$REMOTE_RELEASE/.env" "`$REMOTE_SHARED/.env"

mkdir -p "`$REMOTE_BASE/releases"
ln -sfn "`$REMOTE_RELEASE" "`$REMOTE_CURRENT"
rm -f "`$REMOTE_ARCHIVE"

if [ "`$KEEP_RELEASES" -gt 0 ]; then
  find "`$REMOTE_BASE/releases" -mindepth 1 -maxdepth 1 -type d | sort -r | tail -n +"`$((KEEP_RELEASES + 1))" | xargs -r rm -rf
fi

echo "Deployed to `$REMOTE_CURRENT"
echo "Dashboard: http://`$(hostname -I | awk '{print `$1}'):`$(grep '^DASHBOARD_PORT=' "`$REMOTE_SHARED/.env" | tail -n 1 | cut -d= -f2-)/"
echo "Gateway listener mode: `$(grep '^GATEWAY_LISTENER_MODE=' "`$REMOTE_SHARED/.env" | tail -n 1 | cut -d= -f2-)"
echo "Admin username: `$(grep '^LITEWAF_ADMIN_USERNAME=' "`$REMOTE_SHARED/.env" | tail -n 1 | cut -d= -f2-)"
echo "Admin password: `$(grep '^LITEWAF_ADMIN_PASSWORD=' "`$REMOTE_SHARED/.env" | tail -n 1 | cut -d= -f2-)"
"@

Write-Host "==> Installing LiteWaf on remote host..."
Invoke-Native ssh @SshArgs $RemoteScript

$RemoteEnvOutput = & ssh @SshArgs "grep -E '^(DASHBOARD_PORT|GATEWAY_LISTENER_MODE|GATEWAY_BRIDGE_PORT_RANGE|LITEWAF_ADMIN_USERNAME|LITEWAF_ADMIN_PASSWORD)=' '$RemoteShared/.env' || true"
if ($LASTEXITCODE -ne 0) {
    throw "Failed to read remote ports from $RemoteShared/.env"
}

$RemotePorts = @{}
foreach ($Line in $RemoteEnvOutput) {
    $Parts = $Line -split "=", 2
    if ($Parts.Count -eq 2) {
        $RemotePorts[$Parts[0]] = $Parts[1]
    }
}

$DashboardPort = if ($RemotePorts.ContainsKey("DASHBOARD_PORT")) { $RemotePorts["DASHBOARD_PORT"] } else { "<DASHBOARD_PORT>" }
$AdminUsername = if ($RemotePorts.ContainsKey("LITEWAF_ADMIN_USERNAME")) { $RemotePorts["LITEWAF_ADMIN_USERNAME"] } else { "<LITEWAF_ADMIN_USERNAME>" }
$AdminPassword = if ($RemotePorts.ContainsKey("LITEWAF_ADMIN_PASSWORD")) { $RemotePorts["LITEWAF_ADMIN_PASSWORD"] } else { "<LITEWAF_ADMIN_PASSWORD>" }

Write-Host "==> Cleaning local archive..."
Remove-Item -LiteralPath $ArchivePath -Force

Write-Host ""
Write-Host "Deployment finished."
Write-Host "Dashboard: $(Format-HttpUrl -HostValue $DisplayHost -PortValue $DashboardPort)"
Write-Host "$(Format-GatewayListenerInfo -Values $RemotePorts)"
Write-Host "Admin username: $AdminUsername"
Write-Host "Admin password: $AdminPassword"
Write-Host ""
Write-Host "Remote env file is preserved at: $RemoteShared/.env"
