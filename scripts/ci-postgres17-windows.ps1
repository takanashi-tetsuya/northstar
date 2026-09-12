# Extract pinned ordinary-user test tools; never install a Windows service.
param([Parameter(Mandatory = $true)][string]$Prefix)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$version = '17.11'
$sha256 = '6eabdf00d2893713b75db4336a23c3fdf505f056e217ec6e2e95d901750cfea3'
$url = 'https://get.enterprisedb.com/postgresql/postgresql-17.11-1-windows-x64-binaries.zip'
if (-not [IO.Path]::IsPathFullyQualified($Prefix)) { throw 'Expected an absolute test-tools prefix' }
$Prefix = [IO.Path]::GetFullPath($Prefix).TrimEnd([IO.Path]::DirectorySeparatorChar)
if ($Prefix.Length -le 3) { throw 'Test-tools prefix must not be a drive root' }
$postgres = Join-Path $Prefix 'bin/postgres.exe'
$marker = Join-Path $Prefix '.binary-sha256'
if (Test-Path -LiteralPath $Prefix) {
    if ((Test-Path -LiteralPath $marker -PathType Leaf) -and
        ((Get-Content -LiteralPath $marker -Raw).Trim() -eq $sha256) -and
        (Test-Path -LiteralPath $postgres -PathType Leaf)) {
        $actual = & $postgres --version
        if ($LASTEXITCODE -eq 0 -and $actual -eq "postgres (PostgreSQL) $version") {
            Write-Output "PostgreSQL $version test tools restored"
            exit 0
        }
    }
    throw 'Existing PostgreSQL test-tools cache is invalid'
}
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('northstar-pg17-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporary) | Out-Null
try {
    $archivePath = Join-Path $temporary 'postgresql.zip'
    Invoke-WebRequest -Uri $url -OutFile $archivePath -TimeoutSec 180 -MaximumRetryCount 2
    if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $sha256) {
        throw 'PostgreSQL binary archive checksum mismatch'
    }
    $stage = Join-Path $temporary 'tools'
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    $stageRoot = [IO.Path]::GetFullPath($stage) + [IO.Path]::DirectorySeparatorChar
    $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        foreach ($entry in $archive.Entries) {
            # The EDB archive also includes GUI tools and documentation; the
            # native smoke needs only the command binaries and PG runtime.
            if ($entry.FullName -notmatch '^pgsql/(bin|lib|share)/') { continue }
            $relative = $entry.FullName.Substring('pgsql/'.Length)
            if ($relative -match '\\|:|(^|/)\.\.(/|$)' -or
                (($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000) {
                throw 'Unsafe PostgreSQL archive member'
            }
            $destination = [IO.Path]::GetFullPath((Join-Path $stage $relative))
            if (-not $destination.StartsWith($stageRoot, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'PostgreSQL archive member escaped the private directory'
            }
            if ($relative.EndsWith('/')) {
                [IO.Directory]::CreateDirectory($destination) | Out-Null
                continue
            }
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destination, $false)
        }
    } finally { $archive.Dispose() }
    $actual = & (Join-Path $stage 'bin/postgres.exe') --version
    if ($LASTEXITCODE -ne 0 -or $actual -ne "postgres (PostgreSQL) $version") {
        throw 'Pinned PostgreSQL tools did not execute correctly'
    }
    foreach ($name in @('initdb', 'pg_ctl', 'pg_isready', 'psql', 'createdb')) {
        if (-not (Test-Path -LiteralPath (Join-Path $stage "bin/$name.exe") -PathType Leaf)) {
            throw "Required PostgreSQL tool is missing: $name"
        }
    }
    Set-Content -LiteralPath (Join-Path $stage '.binary-sha256') -Value $sha256 -Encoding ascii
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Prefix)) | Out-Null
    [IO.Directory]::Move($stage, $Prefix)
    Write-Output "PostgreSQL $version test tools verified"
} finally {
    # Only the random directory created by this invocation is removed.
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
