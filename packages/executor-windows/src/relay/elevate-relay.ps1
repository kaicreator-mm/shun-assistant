# Elevation relay for the one-shot privileged helper (L2 §8.2.1).
#
# Performs exactly one Start-Process -Verb RunAs and reports the outcome
# through a relay JSON file. UAC consent/decline surfaces here as a .NET
# exception (secure-desktop prompts are not automatable by Windows design —
# a property this design relies on, never works around). The relay runs
# NON-elevated; stdout/stderr of the elevated child are intentionally NOT
# redirected (Win32 cannot redirect across RunAs): the structured channels
# across the privilege boundary are the envelope (in) and journal + receipt
# (out), never console text.
#
# This file is pinned infrastructure: its content hash is recorded in the
# authority helper-pin and verified by the launcher before every spawn.
param(
  [Parameter(Mandatory = $true)][string] $NodeExe,
  [Parameter(Mandatory = $true)][string] $HelperBundle,
  [Parameter(Mandatory = $true)][string] $HelperArgsJson,
  [Parameter(Mandatory = $true)][string] $RelayFile
)
$ErrorActionPreference = 'Stop'

function ConvertTo-Win32Arg([string]$a) {
  # Windows argv quoting rules (child is parsed by the CRT, not a shell):
  # quote args containing whitespace/quotes, double backslashes before an
  # escaped quote, double trailing backslashes. No shell is involved anywhere.
  if ($a -notmatch '[\s"]') { return $a }
  $escaped = $a -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1'
  return ('"' + $escaped + '"')
}

function Write-Relay($obj) {
  [System.IO.File]::WriteAllText(
    $RelayFile,
    ((ConvertTo-Json -InputObject $obj -Compress) + [Environment]::NewLine),
    (New-Object System.Text.UTF8Encoding($false))
  )
}

try {
  # N-R2-1 (belt-and-braces): the elevated child inherits THIS process's
  # environment through Start-Process -Verb RunAs. The launcher already
  # spawned us with a sterilized minimal environment, but the relay is the
  # last gate before UAC consent: no Node interpreter-directive variable may
  # cross, or NODE_OPTIONS=--require=attacker.js would execute attacker JS
  # inside the pinned elevated node before any self-check. Remove the known
  # names AND sweep the whole NODE_* family.
  foreach ($name in @('NODE_OPTIONS','NODE_PATH','NODE_EXTRA_CA_CERTS','NODE_V8_COVERAGE','NODE_DEBUG','NODE_COMPILE_CACHE','NODE_REPL_EXTERNAL_MODULE')) {
    if (Test-Path "Env:\$name") { Remove-Item "Env:\$name" -ErrorAction SilentlyContinue }
  }
  Get-ChildItem Env: | Where-Object { $_.Name -like 'NODE*' } | ForEach-Object {
    Remove-Item ("Env:\" + $_.Name) -ErrorAction SilentlyContinue
  }
  $helperArgs = @()
  foreach ($a in (ConvertFrom-Json $HelperArgsJson)) { $helperArgs += [string]$a }
  # The helper bundle itself leads the command line, then its argv.
  $argLine = (ConvertTo-Win32Arg $HelperBundle) + ' ' + ((@($helperArgs) | ForEach-Object { ConvertTo-Win32Arg $_ }) -join ' ')
  # One pre-quoted command line: PS 5.1's array -ArgumentList joins with
  # spaces WITHOUT quoting, which breaks paths containing spaces.
  $p = Start-Process -FilePath $NodeExe -ArgumentList $argLine -Verb RunAs -Wait -PassThru -WindowStyle Hidden
  Write-Relay @{ kind = 'RAN'; exitCode = $p.ExitCode; childPid = $p.Id }
  exit 0
} catch {
  $hr = '0x{0:X8}' -f $_.Exception.HResult
  Write-Relay @{ kind = 'UAC_DECLINED'; error = $_.Exception.Message; hresult = $hr }
  exit 10
}
