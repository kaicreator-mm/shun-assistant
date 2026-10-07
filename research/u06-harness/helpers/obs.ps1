# U-06 demo D1: non-elevated read-only observation helper.
# Typed parameters only; structured JSON on stdout; diagnostics on stderr.
# No shell, no arbitrary command endpoint: -Query is a validated enum, every
# other parameter is a typed value consumed by fixed code paths.
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('os.build', 'service.query', 'package.inventory')]
  [string] $Query,

  [string] $Target = '',

  [int] $DelayMs = 0,

  [string] $CancelFile = '',

  # negative-path instrumentation: emit a diagnostic on stderr and exit 3
  [switch] $SimulateFailure
)

function Out-Result($obj) {
  [Console]::Out.WriteLine((ConvertTo-Json -InputObject $obj -Compress -Depth 5))
}

if ($SimulateFailure) {
  [Console]::Error.WriteLine('simulated helper diagnostic: observation channel failure')
  exit 3
}

if ($DelayMs -gt 0) {
  $end = (Get-Date).AddMilliseconds($DelayMs)
  while ((Get-Date) -lt $end) {
    if ($CancelFile -and (Test-Path -LiteralPath $CancelFile)) {
      Out-Result @{ query = $Query; cancelled = $true; delayMs = $DelayMs; observedBeforeCancel = $true }
      exit 5
    }
    Start-Sleep -Milliseconds 200
  }
}

switch ($Query) {
  'os.build' {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    Out-Result @{
      query = $Query
      target = $Target
      os = @{
        productName    = $cv.ProductName
        displayVersion = $cv.DisplayVersion
        currentBuild   = $cv.CurrentBuild
        ubr            = $cv.UBR
        buildString    = ('{0}.{1}.{2}.{3}' -f '10', 0, $cv.CurrentBuild, $cv.UBR)
      }
      cancelled = $false
    }
    exit 0
  }
  'service.query' {
    if (-not $Target) { [Console]::Error.WriteLine('service.query requires -Target'); exit 2 }
    $svc = Get-Service -Name $Target -ErrorAction SilentlyContinue
    if (-not $svc) { [Console]::Error.WriteLine("service not found: $Target"); exit 2 }
    Out-Result @{
      query = $Query
      target = $Target
      service = @{ name = $svc.Name; displayName = $svc.DisplayName; status = [string]$svc.Status; startType = [string]$svc.StartType }
      cancelled = $false
    }
    exit 0
  }
  'package.inventory' {
    $keys = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
      ForEach-Object { Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue } |
      Where-Object { $_ -and $_.DisplayName }
    if ($Target) { $keys = $keys | Where-Object { $_.DisplayName -like ("*" + $Target + "*") } }
    $items = @($keys | Select-Object -First 10 | ForEach-Object {
      @{ displayName = $_.DisplayName; displayVersion = $_.DisplayVersion; publisher = $_.Publisher }
    })
    Out-Result @{
      query = $Query
      target = $Target
      inventory = @{ matchCount = @($keys).Count; sample = $items }
      cancelled = $false
    }
    exit 0
  }
}
[Console]::Error.WriteLine('unreachable')
exit 2
