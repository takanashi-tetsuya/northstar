# Grant the current user SID access even after PostgreSQL drops admin groups.
param([Parameter(Mandatory = $true)][string]$Directory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Write-Output "Preparing private fixture ACL with PowerShell $($PSVersionTable.PSVersion)"
$item = Get-Item -LiteralPath $Directory -Force
if (-not $item.PSIsContainer -or
    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    [IO.Directory]::GetFileSystemEntries($item.FullName).Length -ne 0) {
    throw 'Expected a new, empty, non-reparse fixture directory'
}
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($user)
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($user, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $item.FullName -AclObject $acl
$actual = Get-Acl -LiteralPath $item.FullName
if ($actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $user.Value -or
    -not $actual.AreAccessRulesProtected) {
    throw 'Private fixture directory ACL verification failed'
}
Write-Output 'Private fixture ACL verified for the current user SID'
