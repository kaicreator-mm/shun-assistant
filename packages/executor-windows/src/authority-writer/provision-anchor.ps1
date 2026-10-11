param(
  [Parameter(Mandatory=$true)][string]$AnchorRoot,
  [Parameter(Mandatory=$true)][string]$WriterBundle,
  [Parameter(Mandatory=$true)][string]$NodeExe,
  [Parameter(Mandatory=$true)][string]$BootstrapManifest
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

function Assert-AnchorId([string]$Value, [string]$Name) {
  if ($Value.Length -lt 1 -or $Value.Length -gt 128 -or $Value -cne $Value.ToLowerInvariant() -or $Value -notmatch '^[a-z0-9][a-z0-9._-]*$' -or $Value.Contains('..')) {
    throw "$Name is not a canonical anchor id: $Value"
  }
}

if ($env:OS -ne 'Windows_NT') { throw 'protected anchor provisioning is Windows-only' }
if (Test-Path -LiteralPath $AnchorRoot) {
  throw "anchor root already exists; refusing in-place reprovision/migration: $AnchorRoot"
}
if (-not (Test-Path -LiteralPath $WriterBundle -PathType Leaf)) { throw "writer bundle missing: $WriterBundle" }
if (-not (Test-Path -LiteralPath $NodeExe -PathType Leaf)) { throw "node executable missing: $NodeExe" }
if (-not (Test-Path -LiteralPath $BootstrapManifest -PathType Leaf)) { throw "bootstrap manifest missing: $BootstrapManifest" }

$bootstrap = Get-Content -LiteralPath $BootstrapManifest -Raw | ConvertFrom-Json
if ($null -eq $bootstrap.currentAuthority) { throw 'bootstrap manifest requires currentAuthority' }
if ($null -eq $bootstrap.helperPin) { throw 'bootstrap manifest requires helperPin' }
if ($null -eq $bootstrap.systemToolsPin) { throw 'bootstrap manifest requires systemToolsPin' }
if ($null -eq $bootstrap.policyWindows -or @($bootstrap.policyWindows).Count -lt 1) { throw 'bootstrap manifest requires at least one policyWindow' }

[System.IO.Directory]::CreateDirectory($AnchorRoot) | Out-Null
Set-ProtectedDirectoryAcl $AnchorRoot

# Root is protected before any authority record exists. Children inherit the
# protected DACL; unexpected pre-existing children are impossible because an
# existing root is refused above.
foreach ($relative in @('grants','jobs','jobs\ledger','jobs\window-budget','jobs\receipts','programs','plans')) {
  [System.IO.Directory]::CreateDirectory((Join-Path $AnchorRoot $relative)) | Out-Null
}

$keyBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($keyBytes) } finally { $rng.Dispose() }
$keyFile = Join-Path $AnchorRoot 'grant-hmac.key'
[System.IO.File]::WriteAllText($keyFile, [Convert]::ToBase64String($keyBytes) + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
Set-SecretFileAcl $keyFile

$writerSha = (Get-FileHash -LiteralPath $WriterBundle -Algorithm SHA256).Hash.ToLowerInvariant()
$nodeSha = (Get-FileHash -LiteralPath $NodeExe -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Json (Join-Path $AnchorRoot 'writer-pin.json') ([ordered]@{
  schemaVersion = 'shun.executor-windows.anchor-writer-pin/1'
  writerSha256 = $writerSha
  nodeExeSha256 = $nodeSha
  pinnedAt = [DateTimeOffset]::UtcNow.ToString('o')
})
Write-Json (Join-Path $AnchorRoot 'current-authority.json') $bootstrap.currentAuthority
Write-Json (Join-Path $AnchorRoot 'helper-pin.json') $bootstrap.helperPin
Write-Json (Join-Path $AnchorRoot 'system-tools.json') $bootstrap.systemToolsPin

foreach ($window in @($bootstrap.policyWindows)) {
  Assert-AnchorId ([string]$window.windowId) 'policyWindow.windowId'
  Write-Json (Join-Path $AnchorRoot ("jobs\window-{0}.json" -f $window.windowId)) $window
}
if ($null -ne $bootstrap.programPins) {
  foreach ($pin in @($bootstrap.programPins)) {
    if ([string]::IsNullOrWhiteSpace([string]$pin.programPath)) { throw 'program pin missing programPath' }
    $digest = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes(([string]$pin.programPath).ToLowerInvariant()))
    $key = ([Convert]::ToHexString($digest)).ToLowerInvariant()
    Write-Json (Join-Path $AnchorRoot ("programs\{0}.json" -f $key)) $pin
  }
}

# Re-assert the root ACL after all bootstrap writes. The runtime user keeps
# read/execute only; the secret key remains admin/SYSTEM-only by its explicit ACL.
Set-ProtectedDirectoryAcl $AnchorRoot
Set-SecretFileAcl $keyFile

$result = [ordered]@{
  ok = $true
  anchorRoot = $AnchorRoot
  keyFile = $keyFile
  writerSha256 = $writerSha
  nodeExeSha256 = $nodeSha
  policyWindowCount = @($bootstrap.policyWindows).Count
}
$result | ConvertTo-Json -Compress
