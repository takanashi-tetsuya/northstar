param([string]$Distro = "Ubuntu-24.04")

$ErrorActionPreference = "Stop"
$projectDir = Split-Path -Parent $PSScriptRoot
$resolvedProjectDir = [System.IO.Path]::GetFullPath($projectDir)
if ($resolvedProjectDir -notmatch '^([A-Za-z]):\\(.*)$') {
    throw "The repository must be on a Windows drive mounted by WSL"
}
$projectWsl = "/mnt/$($Matches[1].ToLowerInvariant())/$($Matches[2].Replace('\', '/'))"

$wslScripts = @(
    "scripts/test-certificate-security.sh",
    "scripts/test-log-security.sh",
    "scripts/runtime-tls-test-wsl.sh",
    "scripts/verify-wsl.sh all",
    "scripts/parser-robustness-wsl.sh 30",
    "scripts/database-role-boundary-wsl.sh",
    "scripts/auth-admin-db-wsl.sh",
    "scripts/admin-session-cleanup-db-wsl.sh",
    "scripts/authentication-service-db-wsl.sh",
    "scripts/abuse-reporting-db-wsl.sh",
    "scripts/abuse-key-deployment-db-wsl.sh",
    "scripts/message-pow-db-wsl.sh",
    "scripts/api-operations-db-wsl.sh",
    "scripts/api-pages-db-wsl.sh",
    "scripts/migration-upgrade-wsl.sh",
    "scripts/migration-0056-db-wsl.sh",
    "scripts/rfc7622-identity-db-wsl.sh",
    "scripts/identity-audit-db-wsl.sh",
    "scripts/jid-identity-db-wsl.sh",
    "scripts/authorization-jid-identity-db-wsl.sh",
    "scripts/push-jid-identity-db-wsl.sh",
    "scripts/push-delivery-db-wsl.sh",
    "scripts/mix-jid-identity-db-wsl.sh",
    "scripts/session-jid-identity-db-wsl.sh",
    "scripts/profile-jid-identity-db-wsl.sh",
    "scripts/roster-service-db-wsl.sh",
    "scripts/mam-db-wsl.sh",
    "scripts/mix-mam-db-wsl.sh",
    "scripts/mix-family-db-wsl.sh",
    "scripts/muc-db-wsl.sh",
    "scripts/pie-db-wsl.sh",
    "scripts/privacy-db-wsl.sh",
    "scripts/offline-replay-db-wsl.sh",
    "scripts/pubsub-db-wsl.sh",
    "scripts/pubsub-outbox-db-wsl.sh",
    "scripts/pubsub-wire-wsl.sh",
    "scripts/retention-db-wsl.sh",
    "scripts/sm-db-wsl.sh",
    "scripts/s2s-db-wsl.sh",
    "scripts/upload-db-wsl.sh",
    "scripts/integration-wsl.sh",
    "scripts/message-pow-wire-wsl.sh",
    "scripts/profile-storage-runtime-wsl.sh",
    "scripts/omemo-runtime-wsl.sh",
    "scripts/moderation-runtime-wsl.sh",
    "scripts/mix-runtime-wsl.sh",
    "scripts/federation-wsl.sh",
    "scripts/mix-federation-runtime-wsl.sh",
    "scripts/component-runtime-wsl.sh",
    "scripts/muc-cluster-wsl.sh",
    "scripts/cluster-wsl.sh",
    "scripts/load-1000-wsl.sh",
    "scripts/load-1000-production-wsl.sh",
    "scripts/backup-restore-wsl.sh"
)

& wsl.exe -d $Distro -u root -- bash -lc "cd '$projectWsl' && bash scripts/test-secret-security.sh"
if ($LASTEXITCODE -ne 0) {
    throw "Runtime validation failed: scripts/test-secret-security.sh"
}

foreach ($command in $wslScripts) {
    & wsl.exe -d $Distro -- bash -lc "cd '$projectWsl' && bash $command"
    if ($LASTEXITCODE -ne 0) {
        throw "Runtime validation failed: $command"
    }
}

$runtimeUid = (& wsl.exe -d $Distro -- id -u).Trim()
if ($LASTEXITCODE -ne 0 -or $runtimeUid -notmatch '^[1-9][0-9]*$') {
    throw "Could not resolve the ordinary WSL runtime UID for XEP-0487"
}
& wsl.exe -d $Distro -u root -- env `
    "XEP0487_RUNTIME_UID=$runtimeUid" `
    "CARGO_TARGET_DIR=$projectWsl/target-wsl" `
    "NORTHSTAR_XEP0487_SKIP_BUILD=true" `
    bash -lc "cd '$projectWsl' && bash scripts/xep0487-runtime-wsl.sh"
if ($LASTEXITCODE -ne 0) {
    throw "Runtime validation failed: privileged XEP-0487 fixture"
}

& wsl.exe -d $Distro -- bash -lc "cd '$projectWsl' && S2S_SASL_EXTERNAL_ENABLED=false bash scripts/federation-wsl.sh"
if ($LASTEXITCODE -ne 0) {
    throw "Runtime validation failed: forced XEP-0220 Dialback federation"
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
& $nodeExe (Join-Path $PSScriptRoot "omemo-security-tests.mjs")
if ($LASTEXITCODE -ne 0) {
    throw "Standalone OMEMO security validation failed"
}

& (Join-Path $PSScriptRoot "browser-e2e-windows.ps1") -Distro $Distro
if ($LASTEXITCODE -ne 0) {
    throw "Browser E2E validation failed"
}

Write-Output "NOTE: production certificate/secret preflight is intentionally separate; run scripts/release-preflight.sh --production on the deployment host."
Write-Output "NOTE: scripts/production-encryption-probe.sh is intentionally excluded because it inspects an operator-selected account in the production database."
Write-Output "release runtime validation passed"
