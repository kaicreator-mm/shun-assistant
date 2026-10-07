# U-06 demo: one-shot elevation relay.
# Performs a single Start-Process -Verb RunAs and reports the outcome through a
# relay JSON file. UAC consent/denial surfaces here as a .NET exception; the
# secure desktop is not automatable by Windows design — that is a property the
# demo relies on, not one it works around.
param(
  [Parameter(Mandatory = $true)][string] $HelperScript,
  [Parameter(Mandatory = $true)][string] $HelperArgsJson,
  [Parameter(Mandatory = $true)][string] $RelayFile,
  [Parameter(Mandatory = $true)][string] $StdoutFile,
  [Parameter(Mandatory = $true)][string] $StderrFile
)
$ErrorActionPreference = 'Stop'
# Stdout/stderr of the elevated child are intentionally NOT redirected:
# the structured channels across the privilege boundary are the envelope
# (in), journal + receipt (out). Console text is not a contract channel.
try {
  $helperArgs = @()
  foreach ($a in (ConvertFrom-Json $HelperArgsJson)) { $helperArgs += [string]$a }
  $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $HelperScript) + $helperArgs
  $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -Wait -PassThru -WindowStyle Hidden
  [System.IO.File]::WriteAllText($RelayFile, ((@{ kind = 'RAN'; exitCode = $p.ExitCode; childPid = $p.Id } | ConvertTo-Json -Compress) + [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($false)))
  exit 0
} catch {
  $hr = '0x{0:X8}' -f $_.Exception.HResult
  [System.IO.File]::WriteAllText($RelayFile, ((@{ kind = 'UAC_DECLINED'; error = $_.Exception.Message; hresult = $hr } | ConvertTo-Json -Compress) + [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($false)))
  exit 10
}
