# U-06 demo: privileged ONE-SHOT action helper.
# Contract: exactly one AuthorizedAction envelope file in, one ExecutionReceipt
# out, side-effect journal along the way, then process exit. No listening
# channel, no reuse, no arbitrary shell endpoint.
#
# Validation order matters for the recovery story (D5): every check happens
# BEFORE any side effect; the first side effect can only occur after the
# EXEC_START journal phase of its step.
param(
  [Parameter(Mandatory = $true)][string] $EnvelopeFile,
  [Parameter(Mandatory = $true)][string] $JournalFile,
  [Parameter(Mandatory = $true)][string] $ReceiptFile
)
$ErrorActionPreference = 'Stop'
$helperStartedAt = (Get-Date).ToString('o')

# ---------- canonical JSON + sha256 (must match lib/plan.mjs exactly) ----------
function ConvertTo-JsonString([string]$s) {
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append('"')
  foreach ($ch in $s.ToCharArray()) {
    switch ($ch) {
      '"'  { [void]$sb.Append('\"') }
      '\' { [void]$sb.Append('\\') }
      "`b" { [void]$sb.Append('\b') }
      "`f" { [void]$sb.Append('\f') }
      "`n" { [void]$sb.Append('\n') }
      "`r" { [void]$sb.Append('\r') }
      "`t" { [void]$sb.Append('\t') }
      default {
        if ([int]$ch -lt 0x20) { [void]$sb.Append(('\u{0:x4}' -f [int]$ch)) }
        else { [void]$sb.Append($ch) }
      }
    }
  }
  [void]$sb.Append('"')
  return $sb.ToString()
}
function ConvertTo-CanonicalJson($obj) {
  if ($null -eq $obj) { return 'null' }
  if ($obj -is [bool]) { if ($obj) { return 'true' } else { return 'false' } }
  if ($obj -is [string]) { return (ConvertTo-JsonString $obj) }
  if ($obj -is [int] -or $obj -is [long]) { return ([Convert]::ToString($obj, [Globalization.CultureInfo]::InvariantCulture)) }
  if ($obj -is [double] -or $obj -is [decimal] -or $obj -is [single]) { return ([Convert]::ToString($obj, [Globalization.CultureInfo]::InvariantCulture)) }
  if ($obj -is [System.Array]) { return ('[' + (($obj | ForEach-Object { ConvertTo-CanonicalJson $_ }) -join ',') + ']') }
  $props = @($obj.PSObject.Properties | Sort-Object -Property Name)
  return ('{' + (($props | ForEach-Object { (ConvertTo-JsonString $_.Name) + ':' + (ConvertTo-CanonicalJson $_.Value) }) -join ',') + '}')
}
function Get-Sha256Hex([string]$text) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))
  return ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

# ---------- journal ----------
function Write-Journal([string]$phase, $detail) {
  $e = [ordered]@{ ts = (Get-Date).ToString('o'); pid = $PID; phase = $phase }
  if ($null -ne $detail) { $e.detail = $detail }
  # UTF8 without BOM: the journal is replayed by strict JSONL parsers
  [System.IO.File]::AppendAllText($JournalFile, (ConvertTo-Json -InputObject $e -Compress) + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
}
function Write-JournalPartial([string]$text) {
  # crash simulation support: an append torn mid-write must not corrupt
  # earlier phases when the journal is replayed (JSONL tolerance).
  [System.IO.File]::AppendAllText($JournalFile, $text)
}

# ---------- receipt ----------
$script:sideEffectEvidence = @()
function Exit-WithReceipt([string]$terminal, [string]$reason, [int]$exitCode) {
  $receipt = [ordered]@{
    schemaVersion = 'u06-demo/1'
    actionId      = $script:envObj.actionId
    environmentId = 'local-windows/' + $env:COMPUTERNAME
    providerId    = 'u06.one-shot-helper'
    providerVersion = '0.1.0-demo'
    startedAt     = $helperStartedAt
    finishedAt    = (Get-Date).ToString('o')
    terminal      = $terminal
    reason        = $reason
    exitCode      = $exitCode
    elevated      = $script:isElevated
    planHash      = $script:envObj.planHash
    approvalId    = $script:envObj.approval.approvalId
    sideEffectEvidence = $script:sideEffectEvidence
  }
  $tmp = "$ReceiptFile.tmp"
  [System.IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject $receipt -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
  Move-Item -Path $tmp -Destination $ReceiptFile -Force
  Write-Journal 'RECEIPT_WRITTEN' @{ terminal = $terminal; receiptFile = $ReceiptFile }
  exit $exitCode
}

# ---------- start ----------
Write-Journal 'RECEIVED' @{ envelopeFile = $EnvelopeFile; helperPid = $PID }
$script:envObj = ConvertFrom-Json ([System.IO.File]::ReadAllText($EnvelopeFile))

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
$script:isElevated = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$act = $envObj.action
$deadline = (Get-Date).AddMilliseconds([int]$act.timeoutMs)

function Test-CancelRequested {
  if ($act.cancelFile -and (Test-Path -LiteralPath $act.cancelFile)) {
    Write-Journal 'CANCELLED' @{ cancelFile = $act.cancelFile }
    Exit-WithReceipt 'CANCELLED' 'cancel sentinel observed between phases' 5
  }
}
function Test-Deadline([string]$where) {
  if ((Get-Date) -gt $deadline) {
    Write-Journal 'TIMED_OUT' @{ where = $where }
    Exit-WithReceipt 'TIMED_OUT' "helper-side timeout at $where" 4
  }
}

# ---------- phase 1: schema / typed-op validation ----------
$knownOps = @('proc.elevated-context-check','fs.write','fs.delete','fs.verify',
  'reg.create','reg.set','reg.delete','reg.verify',
  'winget.inventory','winget.install','winget.uninstall','winget.verify')
if ($envObj.schemaVersion -ne 'u06-demo/1') { Write-Journal 'REFUSED' @{ why='schemaVersion' }; Exit-WithReceipt 'REFUSED' 'unknown schemaVersion' 2 }
if ($act.kind -ne 'u06.sequence')           { Write-Journal 'REFUSED' @{ why='kind' };        Exit-WithReceipt 'REFUSED' 'unknown action kind' 2 }
foreach ($s in @($act.steps)) {
  if ($knownOps -notcontains $s.op) { Write-Journal 'REFUSED' @{ why='op'; op=$s.op }; Exit-WithReceipt 'REFUSED' ("unknown op '" + $s.op + "' - no arbitrary shell endpoint") 2 }
}
Write-Journal 'VALIDATED' @{ steps = @($act.steps).Count }

# ---------- phase 2: planHash re-computation across the boundary ----------
$plan = $envObj.plan
$plan.PSObject.Properties.Remove('planHash')
$recomputed = Get-Sha256Hex (ConvertTo-CanonicalJson $plan)
if ($recomputed -ne $envObj.planHash) {
  Write-Journal 'REFUSED' @{ why = 'planHash mismatch'; expected = $envObj.planHash; recomputed = $recomputed }
  Exit-WithReceipt 'REFUSED' 'plan hash mismatch - plan does not match the authorized hash' 2
}
Write-Journal 'PLANHASH_OK' @{ planHash = $recomputed }

# ---------- phase 3: approval binding ----------
if (-not $envObj.approval -or $envObj.approval.planHash -ne $envObj.planHash) {
  Write-Journal 'REFUSED' @{ why = 'approval not bound to planHash' }
  Exit-WithReceipt 'REFUSED' 'approval is not bound to the exact planHash' 2
}
if ($envObj.authorizationRef.approvalId -ne $envObj.approval.approvalId) {
  Write-Journal 'REFUSED' @{ why = 'authorizationRef mismatch' }
  Exit-WithReceipt 'REFUSED' 'authorizationRef does not match approval' 2
}
$expiry = [DateTime]::Parse($envObj.approval.expiresAt, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
if ((Get-Date).ToUniversalTime() -gt $expiry) {
  Write-Journal 'REFUSED' @{ why = 'approval expired'; expiresAt = $envObj.approval.expiresAt }
  Exit-WithReceipt 'REFUSED' 'approval expired' 2
}
Write-Journal 'APPROVAL_OK' @{ approvalId = $envObj.approval.approvalId; authorizationKind = $envObj.authorizationKind }

# ---------- phase 4: scope enforcement (all steps, before any effect) ----------
function Test-PathInScope([string]$path) {
  $full = [System.IO.Path]::GetFullPath($path)
  foreach ($root in @($act.scope.filesystem.allowedRoots)) {
    $rootFull = [System.IO.Path]::GetFullPath($root).TrimEnd('\')
    if ($full.ToLowerInvariant().StartsWith($rootFull.ToLowerInvariant() + '\')) { return $full }
  }
  Write-Journal 'REFUSED' @{ why = 'scope: filesystem'; path = $full }
  Exit-WithReceipt 'REFUSED' ("filesystem path outside declared scope: " + $full) 2
}
function Test-KeyInScope([string]$key) {
  foreach ($k in @($act.scope.registry.allowedKeys)) {
    if ($key.ToLowerInvariant().StartsWith($k.ToLowerInvariant())) { return }
  }
  Write-Journal 'REFUSED' @{ why = 'scope: registry'; key = $key }
  Exit-WithReceipt 'REFUSED' ("registry key outside declared scope: " + $key) 2
}
foreach ($s in @($act.steps)) {
  try {
    switch -Regex ($s.op) {
      '^fs\.'   { Test-PathInScope $s.args.path | Out-Null }
      '^reg\.'  { Test-KeyInScope $s.args.key }
      '^winget\.' {
        if (@($act.scope.process.allowedPrograms) -notcontains 'winget.exe') {
          Write-Journal 'REFUSED' @{ why = 'scope: process winget.exe not allowed' }
          Exit-WithReceipt 'REFUSED' 'winget.exe not in declared process scope' 2
        }
        # inventory has no package target; package-scoped ops must match the plan
        if ($s.args.id -and @($act.scope.packages) -notcontains $s.args.id) {
          Write-Journal 'REFUSED' @{ why = 'scope: package'; id = $s.args.id }
          Exit-WithReceipt 'REFUSED' ("package not in declared scope: " + $s.args.id) 2
        }
      }
    }
  } catch {
    # fail closed: invalid typed data (e.g. illegal path characters) is a
    # structured refusal, never a crash without receipt
    Write-Journal 'REFUSED' @{ why = 'scope validation error'; error = $_.Exception.Message }
    Exit-WithReceipt 'REFUSED' ("scope validation error: " + $_.Exception.Message) 2
  }
}
Write-Journal 'SCOPE_OK' @{}

# ---------- phase 5: privilege consistency ----------
$integrity = if ($script:isElevated) { 'high (admin, elevated token)' } else { 'medium (filtered token)' }
if ($act.requiredPrivilege -eq 'elevated-admin' -and -not $script:isElevated) {
  Write-Journal 'REFUSED' @{ why = 'requiredPrivilege'; isElevated = $false }
  Exit-WithReceipt 'REFUSED' 'action requires elevated admin context but helper token is filtered' 2
}
Write-Journal 'ELEVATION_OK' @{ isElevated = $script:isElevated; integrity = $integrity }

# ---------- typed command-line quoting (Windows argv rules, no shell) ----------
function ConvertTo-CommandLineArg([string]$a) {
  if ($a -notmatch '[\s"]') { return $a }
  $escaped = $a -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1'
  return ('"' + $escaped + '"')
}

# ---------- step executors ----------
function Invoke-ExeCaptured([string]$exe, [string[]]$argList, [int]$timeoutMs) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $exe
  $psi.Arguments = ($argList | ForEach-Object { ConvertTo-CommandLineArg $_ }) -join ' '
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  $so = $p.StandardOutput.ReadToEndAsync()
  $se = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($timeoutMs)) {
    try { $p.Kill() } catch {}
    return @{ timedOut = $true; exitCode = $null; stdout = ''; stderr = 'killed by helper-side timeout' }
  }
  return @{ timedOut = $false; exitCode = $p.ExitCode; stdout = $so.Result; stderr = $se.Result }
}

function Invoke-Step($s, [int]$index) {
  Test-CancelRequested
  Test-Deadline ("step:$($s.op)")
  Write-Journal 'EXEC_START' @{ step = $index; op = $s.op }
  if ($act.fault -and $act.fault.beforeStepEffect -eq $index) {
    if ($act.fault.mode -eq 'torn') { Write-JournalPartial ('{"ts":"torn","phase":"EXEC_ST') }
    Write-Journal 'SIMULATED_CRASH' @{ at = 'beforeStepEffect'; step = $index }
    & "$env:SystemRoot\System32\taskkill.exe" /F /PID $PID | Out-Null
    Start-Sleep -Seconds 5  # unreachable: process is dead
  }
  $result = $null
  try {
  switch ($s.op) {
    'proc.elevated-context-check' {
      $ok = $script:isElevated -eq [bool]$s.args.expectElevated
      $result = @{ expectElevated = [bool]$s.args.expectElevated; actualElevated = $script:isElevated }
      if (-not $ok) { return @{ op = $s.op; status = 'FAILED'; result = $result; reason = 'elevation context mismatch' } }
    }
    'fs.write' {
      $p = Test-PathInScope $s.args.path
      [System.IO.File]::WriteAllText($p, [string]$s.args.content, (New-Object System.Text.UTF8Encoding($false)))
      $result = @{ path = $p; bytes = ([System.Text.Encoding]::UTF8.GetByteCount([string]$s.args.content)) }
    }
    'fs.delete' {
      $p = Test-PathInScope $s.args.path
      $existed = Test-Path -LiteralPath $p
      if ($existed) { Remove-Item -LiteralPath $p -Force }
      $result = @{ path = $p; existed = $existed }
    }
    'fs.verify' {
      $p = Test-PathInScope $s.args.path
      $exists = Test-Path -LiteralPath $p
      $contentOk = $true
      if ($exists -and ($null -ne $s.args.expectContent)) {
        $contentOk = ([System.IO.File]::ReadAllText($p) -eq [string]$s.args.expectContent)
      }
      $result = @{ path = $p; exists = $exists; contentMatches = $contentOk }
      if (-not $exists -or -not $contentOk) { return @{ op = $s.op; status = 'FAILED'; result = $result; reason = 'post-state check failed inside helper' } }
    }
    'reg.create' {
      Test-KeyInScope $s.args.key
      New-Item -Path $s.args.key -Force | Out-Null
      $result = @{ key = $s.args.key }
    }
    'reg.set' {
      Test-KeyInScope $s.args.key
      Set-ItemProperty -LiteralPath $s.args.key -Name $s.args.name -Value ([string]$s.args.value) -Type String
      $result = @{ key = $s.args.key; name = $s.args.name; value = $s.args.value }
    }
    'reg.delete' {
      Test-KeyInScope $s.args.key
      if (Test-Path -LiteralPath $s.args.key) { Remove-Item -LiteralPath $s.args.key -Recurse -Force }
      $result = @{ key = $s.args.key }
    }
    'reg.verify' {
      Test-KeyInScope $s.args.key
      $checks = @{}
      $ok = $true
      $exists = Test-Path -LiteralPath $s.args.key
      if ($null -ne $s.args.expectKeyExists) {
        $matchKey = ($exists -eq [bool]$s.args.expectKeyExists)
        $checks['__keyExists'] = @{ expected = [bool]$s.args.expectKeyExists; actual = $exists; match = $matchKey }
        if (-not $matchKey) { $ok = $false }
      }
      foreach ($prop in $s.args.expectValues.PSObject.Properties) {
        $actual = $null
        if ($exists) {
          $kp = Get-ItemProperty -LiteralPath $s.args.key
          $actual = $kp.($prop.Name)
        }
        $match = ($null -ne $actual -and [string]$actual -eq [string]$prop.Value)
        $checks[$prop.Name] = @{ expected = [string]$prop.Value; actual = $actual; match = $match }
        if (-not $match) { $ok = $false }
      }
      $result = @{ key = $s.args.key; checks = $checks }
      if (-not $ok) { return @{ op = $s.op; status = 'FAILED'; result = $result; reason = 'registry post-state mismatch' } }
    }
    'winget.inventory' {
      $r = Invoke-ExeCaptured $s.args.wingetPath @('list','--disable-interactivity') ([int]$act.timeoutMs)
      $result = @{ exitCode = $r.exitCode; timedOut = $r.timedOut; outputSample = (@($r.stdout -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 12) }
      if ($r.timedOut) { return @{ op = $s.op; status = 'TIMED_OUT'; result = $result; reason = 'winget exceeded helper-side deadline' } }
      if ($r.exitCode -ne 0) { return @{ op = $s.op; status = 'FAILED'; result = $result; reason = 'winget list failed' } }
    }
    'winget.install' {
      $argList = @('install','--id',$s.args.id,'--exact','--silent','--accept-package-agreements','--accept-source-agreements','--disable-interactivity')
      if ($s.args.version) { $argList += @('--version', $s.args.version) }
      if ($s.args.scope)   { $argList += @('--scope', $s.args.scope) }
      $r = Invoke-ExeCaptured $s.args.wingetPath $argList ([int]$act.timeoutMs)
      $result = @{ exitCode = $r.exitCode; timedOut = $r.timedOut; outputTail = (@($r.stdout -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -Last 6); stderr = $r.stderr }
      if ($r.timedOut) { return @{ op = $s.op; status = 'TIMED_OUT'; result = $result; reason = 'winget install exceeded helper-side deadline' } }
      if ($r.exitCode -ne 0) { return @{ op = $s.op; status = 'FAILED'; result = $result; reason = 'winget install failed' } }
    }
    'winget.uninstall' {
      $r = Invoke-ExeCaptured $s.args.wingetPath @('uninstall','--id',$s.args.id,'--exact','--silent','--disable-interactivity') ([int]$act.timeoutMs)
      $result = @{ exitCode = $r.exitCode; timedOut = $r.timedOut; outputTail = (@($r.stdout -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -Last 6); stderr = $r.stderr }
      if ($r.timedOut) { return @{ op = $s.op; status = 'TIMED_OUT'; result = $result; reason = 'winget uninstall exceeded helper-side deadline' } }
      if ($r.exitCode -ne 0) { return @{ op = $s.op; status = 'FAILED'; result = $result; reason = 'winget uninstall failed' } }
    }
    'winget.verify' {
      # registry uninstall evidence (typed display pattern, -LiteralPath), plus
      # a winget list capture as corroborating output (non-fatal either way)
      $uninstKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
      $found = @(Get-ChildItem -LiteralPath $uninstKey -ErrorAction SilentlyContinue | Where-Object {
        $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
        $p -and $p.DisplayName -like $s.args.displayPattern
      } | Select-Object -First 3)
      $details = @($found | ForEach-Object {
        $p = Get-ItemProperty -LiteralPath $_.PSPath
        @{ key = $_.PSChildName; displayName = $p.DisplayName; displayVersion = $p.DisplayVersion; publisher = $p.Publisher; installDate = $p.InstallDate }
      })
      $installed = $details.Count -gt 0
      $ok = ($installed -eq [bool]$s.args.expectInstalled)
      $wingetList = Invoke-ExeCaptured $s.args.wingetPath @('list','--id',$s.args.id,'--exact','--disable-interactivity') 60000
      $result = @{ id = $s.args.id; expectInstalled = [bool]$s.args.expectInstalled; installed = $installed; registryEvidence = $details; wingetListExit = $wingetList.exitCode; wingetListTail = (@($wingetList.stdout -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -Last 4) }
      if (-not $ok) { return @{ op = $s.op; status = 'FAILED'; result = $result; reason = 'package presence post-state mismatch' } }
    }
    default {
      return @{ op = $s.op; status = 'FAILED'; result = $null; reason = 'unreachable: op enum pre-validated' }
    }
  }
  } catch {
    # fail closed: an exception inside a step executor is a structured
    # FAILED receipt, never a crash without receipt
    return @{ op = $s.op; status = 'FAILED'; result = @{ error = $_.Exception.Message; type = $_.Exception.GetType().Name }; reason = ("exception in step: " + $_.Exception.Message) }
  }
  if ($act.fault -and $act.fault.afterStep -eq $index) {
    if ($act.fault.mode -eq 'torn') { Write-JournalPartial ('{"ts":"torn","phase":"EXEC_DO') }
    Write-Journal 'SIMULATED_CRASH' @{ at = 'afterStep'; step = $index }
    & "$env:SystemRoot\System32\taskkill.exe" /F /PID $PID | Out-Null
    Start-Sleep -Seconds 5  # unreachable: process is dead
  }
  Write-Journal 'EXEC_DONE' @{ step = $index; op = $s.op }
  $script:sideEffectEvidence += @{ step = $index; op = $s.op; result = $result }
  return @{ op = $s.op; status = 'OK'; result = $result }
}

# ---------- main loop ----------
Write-Journal 'EXEC_BEGIN' @{ totalSteps = @($act.steps).Count }
$stepResults = @()
for ($i = 0; $i -lt @($act.steps).Count; $i++) {
  $r = Invoke-Step $act.steps[$i] $i
  $stepResults += $r
  if ($r.status -ne 'OK') {
    $terminal = if ($r.status -eq 'TIMED_OUT') { 'TIMED_OUT' } else { 'FAILED' }
    $code = if ($terminal -eq 'TIMED_OUT') { 4 } else { 3 }
    Exit-WithReceipt $terminal ("step $i ($($r.op)): $($r.reason)") $code
  }
}
Exit-WithReceipt 'OK' 'all steps completed' 0
