param(
  [Parameter(Mandatory=$true)][string]$AnchorRoot,
  [Parameter(Mandatory=$true)][string]$WriterBundle,
  [Parameter(Mandatory=$true)][string]$HelperBundle,
  [Parameter(Mandatory=$true)][string]$RelayScript,
  [Parameter(Mandatory=$true)][string]$NodeExe,
  [Parameter(Mandatory=$true)][string]$WorkspaceRoot,
  [Parameter(Mandatory=$true)][string]$BootstrapManifest,
  [string]$HelperRevision = 'shun.executor-windows.helper/0.1.0'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function New-AllowRule([System.Security.Principal.SecurityIdentifier]$Sid, [System.Security.AccessControl.FileSystemRights]$Rights, [System.Security.AccessControl.InheritanceFlags]$Inheritance) {
  return New-Object System.Security.AccessControl.FileSystemAccessRule(
    $Sid,
    $Rights,
    $Inheritance,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
}

function Set-ProtectedDirectoryAcl([string]$Path) {
  $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
  $users = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $acl.SetOwner($admins)
  $acl.SetAccessRuleProtection($true, $false)
  $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
  $acl.AddAccessRule((New-AllowRule $admins ([System.Security.AccessControl.FileSystemRights]::FullControl) $inherit))
  $acl.AddAccessRule((New-AllowRule $system ([System.Security.AccessControl.FileSystemRights]::FullControl) $inherit))
  $acl.AddAccessRule((New-AllowRule $users ([System.Security.AccessControl.FileSystemRights]'ReadAndExecute,Synchronize') $inherit))
  Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-PrivilegedOwner([string]$Path) {
  $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $acl = Get-Acl -LiteralPath $Path
  $acl.SetOwner($admins)
  Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-SecretFileAcl([string]$Path) {
  $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
  $acl = New-Object System.Security.AccessControl.FileSecurity
  $acl.SetOwner($admins)
  $acl.SetAccessRuleProtection($true, $false)
  $none = [System.Security.AccessControl.InheritanceFlags]::None
  $acl.AddAccessRule((New-AllowRule $admins ([System.Security.AccessControl.FileSystemRights]::FullControl) $none))
  $acl.AddAccessRule((New-AllowRule $system ([System.Security.AccessControl.FileSystemRights]::FullControl) $none))
  Set-Acl -LiteralPath $Path -AclObject $acl
}

function Write-Json([string]$Path, $Value) {
  $json = $Value | ConvertTo-Json -Depth 64
  [System.IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
}

function File-Sha256([string]$Path) {
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-File([string]$Path, [string]$Name) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Name missing: $Path" }
}

function Assert-AnchorId([string]$Value, [string]$Name) {
  if ($Value.Length -lt 1 -or $Value.Length -gt 128 -or $Value -cne $Value.ToLowerInvariant() -or $Value -notmatch '^[a-z0-9][a-z0-9._-]*$' -or $Value.Contains('..')) {
    throw "$Name is not a canonical anchor id: $Value"
  }
}

if ($env:OS -ne 'Windows_NT') { throw 'protected anchor provisioning is Windows-only' }
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'protected anchor provisioning requires an elevated Administrator token'
}
if (Test-Path -LiteralPath $AnchorRoot) {
  throw "anchor root already exists; refusing in-place reprovision/migration: $AnchorRoot"
}
Assert-File $WriterBundle 'writer bundle'
Assert-File $HelperBundle 'helper bundle'
Assert-File $RelayScript 'elevation relay'
Assert-File $NodeExe 'node executable'
Assert-File $BootstrapManifest 'bootstrap manifest'
if (-not (Test-Path -LiteralPath $WorkspaceRoot -PathType Container)) {
  throw "workspace root missing: $WorkspaceRoot"
}

# Infrastructure identity is measured HERE, in the elevated bootstrap
# ceremony. The untrusted manifest never supplies executable hashes.
$systemDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
if ([string]::IsNullOrWhiteSpace($systemDir)) { throw 'Windows system directory unavailable' }
$whoamiExe = Join-Path $systemDir 'whoami.exe'
$regExe = Join-Path $systemDir 'reg.exe'
$taskkillExe = Join-Path $systemDir 'taskkill.exe'
$powershellExe = Join-Path $systemDir 'WindowsPowerShell\v1.0\powershell.exe'
foreach ($pair in @(
  @($whoamiExe, 'whoami.exe'),
  @($regExe, 'reg.exe'),
  @($taskkillExe, 'taskkill.exe'),
  @($powershellExe, 'powershell.exe')
)) {
  Assert-File $pair[0] $pair[1]
}

$bootstrap = Get-Content -LiteralPath $BootstrapManifest -Raw | ConvertFrom-Json
if ($null -eq $bootstrap.currentAuthority) { throw 'bootstrap manifest requires currentAuthority' }
if ($null -eq $bootstrap.policyWindows -or @($bootstrap.policyWindows).Count -lt 1) {
  throw 'bootstrap manifest requires at least one policyWindow'
}

[System.IO.Directory]::CreateDirectory($AnchorRoot) | Out-Null
# Protect the root BEFORE writing any authority record.
Set-ProtectedDirectoryAcl $AnchorRoot
foreach ($relative in @('grants','jobs','jobs\ledger','jobs\window-budget','jobs\receipts','programs')) {
  [System.IO.Directory]::CreateDirectory((Join-Path $AnchorRoot $relative)) | Out-Null
}

$keyBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($keyBytes) } finally { $rng.Dispose() }
$keyFile = Join-Path $AnchorRoot 'grant-hmac.key'
[System.IO.File]::WriteAllText(
  $keyFile,
  [Convert]::ToBase64String($keyBytes) + [Environment]::NewLine,
  [System.Text.UTF8Encoding]::new($false)
)
Set-SecretFileAcl $keyFile

$now = [DateTimeOffset]::UtcNow.ToString('o')
$nodeSha = File-Sha256 $NodeExe
Write-Json (Join-Path $AnchorRoot 'writer-pin.json') ([ordered]@{
  schemaVersion = 'shun.executor-windows.anchor-writer-pin/1'
  writerSha256 = File-Sha256 $WriterBundle
  nodeExeSha256 = $nodeSha
  pinnedAt = $now
})
Write-Json (Join-Path $AnchorRoot 'helper-pin.json') ([ordered]@{
  schemaVersion = 'shun.executor-windows.helper-pin/1'
  helperRevision = $HelperRevision
  helperSha256 = File-Sha256 $HelperBundle
  relaySha256 = File-Sha256 $RelayScript
  nodeExeSha256 = $nodeSha
  workspaceRoot = [System.IO.Path]::GetFullPath($WorkspaceRoot)
  pinnedAt = $now
})
Write-Json (Join-Path $AnchorRoot 'system-tools.json') ([ordered]@{
  schemaVersion = 'shun.executor-windows.system-tools-pin/1'
  whoamiSha256 = File-Sha256 $whoamiExe
  regSha256 = File-Sha256 $regExe
  powershellSha256 = File-Sha256 $powershellExe
  taskkillSha256 = File-Sha256 $taskkillExe
  pinnedAt = $now
})
Write-Json (Join-Path $AnchorRoot 'current-authority.json') $bootstrap.currentAuthority

foreach ($window in @($bootstrap.policyWindows)) {
  Assert-AnchorId ([string]$window.windowId) 'policyWindow.windowId'
  Write-Json (Join-Path $AnchorRoot ("jobs\window-{0}.json" -f $window.windowId)) $window
}

# Re-assert after bootstrap writes. Ownership is an independent security
# condition: an owner implicitly holds WRITE_DAC even when its current ACEs
# deny write. Every initial child is therefore moved to Administrators owner,
# not merely the root/key.
Get-ChildItem -LiteralPath $AnchorRoot -Force -Recurse | ForEach-Object {
  Set-PrivilegedOwner $_.FullName
}
Set-ProtectedDirectoryAcl $AnchorRoot
Set-SecretFileAcl $keyFile

$result = [ordered]@{
  ok = $true
  anchorRoot = [System.IO.Path]::GetFullPath($AnchorRoot)
  keyFile = [System.IO.Path]::GetFullPath($keyFile)
  writerSha256 = File-Sha256 $WriterBundle
  helperSha256 = File-Sha256 $HelperBundle
  relaySha256 = File-Sha256 $RelayScript
  nodeExeSha256 = $nodeSha
  policyWindowCount = @($bootstrap.policyWindows).Count
}
$result | ConvertTo-Json -Compress
