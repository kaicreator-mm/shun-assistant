# i85-U01 R2 independent observer — non-elevated snapshot poller keyed on the
# staged node.exe executable path (so observation starts BEFORE the child pid
# exists), recording every TCP connection state of the matched processes, any
# connection touching the watched sink ports, and (1s cadence) any helper
# processes parented by the matched pids. Research-only; runs outside the sandbox.
param(
  [Parameter(Mandatory=$true)][int]$Seconds,
  [Parameter(Mandatory=$true)][string]$OutFile,
  [string[]]$MatchPaths = @(),
  [string]$WatchPortsCsv = ''
)
if (Test-Path -LiteralPath $OutFile) {
  [Console]::Error.WriteLine('OBSR2 preflight FILE_ALREADY_EXISTS')
  exit 17
}
[int[]]$WatchPorts = @()
if ($WatchPortsCsv) {
  $WatchPorts = @($WatchPortsCsv -split ',' | Where-Object { $_.Trim() -ne '' } | ForEach-Object { [int]$_.Trim() })
}
$start = Get-Date
$sw = [System.IO.StreamWriter]::new($OutFile, $false)
# AutoFlush: a killed observer must not lose its buffered evidence lines
# (the R2 first sandbox run lost the inference-window records this way).
$sw.AutoFlush = $true
try {
  $sw.WriteLine('# observer start ' + $start.ToString('o'))
  $sw.WriteLine('# matchPaths ' + ($MatchPaths -join ' | '))
  $pathCache = @{}
  $tick = 0
  while (((Get-Date) - $start).TotalSeconds -lt $Seconds) {
    $tick++
    $ts = (Get-Date).ToString('o')
    try {
      $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue
      $matchedPids = @()
      foreach ($c in $conns) {
        $p = [int]$c.OwningProcess
        if (-not $pathCache.ContainsKey($p)) {
          $gp = Get-Process -Id $p -ErrorAction SilentlyContinue
          $gpPath = ''
          if ($gp -and $gp.Path) { $gpPath = [string]$gp.Path }
          $pathCache[$p] = $gpPath
        }
        $path = [string]$pathCache[$p]
        $isMatch = $false
        foreach ($m in $MatchPaths) { if ($path -ieq $m) { $isMatch = $true; break } }
        $touchesWatch = ($WatchPorts -contains [int]$c.RemotePort) -or ($WatchPorts -contains [int]$c.LocalPort)
        if ($isMatch -or $touchesWatch) {
          if ($isMatch -and $matchedPids -notcontains $p) { $matchedPids += $p }
          $sw.WriteLine($ts + ' kind=conn pid=' + $p + ' state=' + $c.State + ' ' +
            $c.LocalAddress + ':' + $c.LocalPort + ' -> ' + $c.RemoteAddress + ':' + $c.RemotePort +
            ' match=' + $isMatch)
        }
      }
      if (($tick % 10) -eq 0 -and $matchedPids.Count -gt 0) {
        foreach ($mp in $matchedPids) {
          try {
            $kids = Get-CimInstance -ClassName Win32_Process -Filter "ParentProcessId=$mp" -ErrorAction SilentlyContinue
            foreach ($k in $kids) {
              $sw.WriteLine($ts + ' kind=childof parent=' + $mp + ' childPid=' + $k.ProcessId +
                ' name=' + $k.Name + ' exe=' + $k.ExecutablePath)
            }
          } catch {}
        }
      }
    } catch {}
    Start-Sleep -Milliseconds 100
  }
  $sw.WriteLine('# observer end ' + (Get-Date).ToString('o'))
} finally { $sw.Close() }
