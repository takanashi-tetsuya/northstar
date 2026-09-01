param(
    [string]$Distro = "Ubuntu-24.04",
    [string]$HostAddress = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
$projectDir = Split-Path -Parent $PSScriptRoot
$resolvedProjectDir = [System.IO.Path]::GetFullPath($projectDir)
if ($resolvedProjectDir -notmatch '^([A-Za-z]):\\(.*)$') {
    throw "The repository must be on a Windows drive mounted by WSL"
}
$projectWsl = "/mnt/$($Matches[1].ToLowerInvariant())/$($Matches[2].Replace('\', '/'))"

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

& wsl.exe -d $Distro -- env `
    "NORTHSTAR_BROWSER_HOST=$HostAddress" `
    "NORTHSTAR_NODE_EXE=$nodeExe" `
    bash "$projectWsl/scripts/browser-e2e-wsl.sh"
if ($LASTEXITCODE -ne 0) {
    throw "Browser E2E validation failed with exit code $LASTEXITCODE"
}
