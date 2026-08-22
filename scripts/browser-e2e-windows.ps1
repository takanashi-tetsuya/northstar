param(
    [string]$Distro = "Ubuntu-24.04",
    [string]$HostAddress = "127.0.0.1",
    [int]$HttpPort = 18380
)

$ErrorActionPreference = "Stop"
$projectDir = Split-Path -Parent $PSScriptRoot
$resolvedProjectDir = [System.IO.Path]::GetFullPath($projectDir)
if ($resolvedProjectDir -notmatch '^([A-Za-z]):\\(.*)$') {
    throw "The repository must be on a Windows drive mounted by WSL"
}
$projectWsl = "/mnt/$($Matches[1].ToLowerInvariant())/$($Matches[2].Replace('\', '/'))"

$serverScript = "$projectWsl/scripts/browser-e2e-server-wsl.sh"
$webTest = Join-Path $PSScriptRoot "web-e2e.cjs"
$url = "http://${HostAddress}:$HttpPort"
$started = $false

try {
    $startArguments = @(
        "-d", $Distro, "--", "env",
        "NORTHSTAR_BROWSER_HOST=$HostAddress",
        "NORTHSTAR_BROWSER_HTTP_PORT=$HttpPort",
        "bash", $serverScript, "start"
    )
    & wsl.exe @startArguments
    if ($LASTEXITCODE -ne 0) {
        throw "The WSL browser E2E server did not start"
    }
    $started = $true

    $ready = $false
    for ($attempt = 0; $attempt -lt 150; $attempt++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$url/readyz" -TimeoutSec 2 | Out-Null
            $ready = $true
            break
        } catch {
            Start-Sleep -Milliseconds 100
        }
    }
    if (-not $ready) {
        throw "Windows could not reach the WSL browser E2E server at $url"
    }

    $nodeCandidates = @()
    if ($env:NORTHSTAR_NODE_EXE) {
        $nodeCandidates += $env:NORTHSTAR_NODE_EXE
    }
    $nodeCommand = Get-Command node.exe -ErrorAction SilentlyContinue
    if ($nodeCommand) {
        $nodeCandidates += $nodeCommand.Source
    }
    $nodeCandidates += Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
    $nodeExe = $nodeCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
    if (-not $nodeExe) {
        throw "Windows Node.js was not found; set NORTHSTAR_NODE_EXE"
    }

    & $nodeExe $webTest $url
    if ($LASTEXITCODE -ne 0) {
        throw "Browser E2E failed with exit code $LASTEXITCODE"
    }
} finally {
    if ($started) {
        $stopArguments = @(
            "-d", $Distro, "--", "env",
            "NORTHSTAR_BROWSER_HOST=$HostAddress",
            "NORTHSTAR_BROWSER_HTTP_PORT=$HttpPort",
            "bash", $serverScript, "stop"
        )
        & wsl.exe @stopArguments
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "The browser E2E server could not be stopped cleanly"
        }
    }
}
