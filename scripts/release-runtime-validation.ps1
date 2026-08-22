param([string]$Distro = "Ubuntu-24.04")

$ErrorActionPreference = "Stop"
$projectDir = Split-Path -Parent $PSScriptRoot
$resolvedProjectDir = [System.IO.Path]::GetFullPath($projectDir)
if ($resolvedProjectDir -notmatch '^([A-Za-z]):\\(.*)$') {
    throw "The repository must be on a Windows drive mounted by WSL"
}
$projectWsl = "/mnt/$($Matches[1].ToLowerInvariant())/$($Matches[2].Replace('\', '/'))"

$wslScripts = @(
    "scripts/verify-wsl.sh all",
    "scripts/integration-wsl.sh",
    "scripts/federation-wsl.sh",
    "scripts/load-1000-wsl.sh",
    "scripts/backup-restore-wsl.sh"
)
foreach ($command in $wslScripts) {
    & wsl.exe -d $Distro -- bash -lc "cd '$projectWsl' && bash $command"
    if ($LASTEXITCODE -ne 0) {
        throw "Runtime validation failed: $command"
    }
}

& (Join-Path $PSScriptRoot "browser-e2e-windows.ps1") -Distro $Distro
if ($LASTEXITCODE -ne 0) {
    throw "Browser E2E validation failed"
}

Write-Output "release runtime validation passed"
