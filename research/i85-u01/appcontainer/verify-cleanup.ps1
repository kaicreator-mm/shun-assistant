# i85-U01 cleanup verification — prove zero leftover ShunU01* AppContainer
# profiles after all probe runs (registry storage keys + Packages dirs).
$storage = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage'
$keys = Get-ChildItem $storage -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like 'shunu01*' }
$pkgs = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Packages') -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'shunu01*' }
Write-Output ("regLeftover=" + @($keys).Count)
Write-Output ("pkgLeftover=" + @($pkgs).Count)
foreach ($k in $keys) { Write-Output ("REG: " + $k.PSChildName) }
foreach ($p in $pkgs) { Write-Output ("PKG: " + $p.Name) }
