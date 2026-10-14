# i85-U01 independent network observer — non-elevated snapshot poller.
# Records TCP connection attempts (SynSent/Bound) and any traffic touching the
# two sink ports, with owning PID, so probe-child activity can be attributed
# after the fact from probe.json's pid. Research-only; runs outside the sandbox.
param(
  [int]$Seconds = 45,
  [string]$OutFile,
  [int[]]$WatchPorts = @(63801, 63802)
)
$start = Get-Date
$sw = [System.IO.StreamWriter]::new($OutFile, $false)
try {
  $sw.WriteLine('# observer start ' + $start.ToString('o'))
  while (((Get-Date) - $start).TotalSeconds -lt $Seconds) {
    $ts = (Get-Date).ToString('o')
    try {
      $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue
      foreach ($c in $conns) {
        if ($c.State -in @('SynSent','Bound') -or
            $WatchPorts -contains [int]$c.RemotePort -or
            $WatchPorts -contains [int]$c.LocalPort) {
          $sw.WriteLine($ts + ' pid=' + $c.OwningProcess + ' ' + $c.LocalAddress + ':' + $c.LocalPort + ' -> ' + $c.RemoteAddress + ':' + $c.RemotePort + ' state=' + $c.State)
        }
      }
    } catch {}
    Start-Sleep -Milliseconds 100
  }
  $sw.WriteLine('# observer end ' + (Get-Date).ToString('o'))
} finally { $sw.Close() }
