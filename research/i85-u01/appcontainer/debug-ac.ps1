# i85-U01 step 4b debug — pinpoint the UpdateProcThreadAttribute failure.
# Minimal sequence: init attr list, build SECURITY_CAPABILITIES, try update
# with explicit sizes, print every intermediate value.
param(
  [Parameter(Mandatory=$true)][string]$ContainerName
)
$ErrorActionPreference = 'Continue'

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class AcDbg {
  [DllImport("userenv.dll", SetLastError=true)]
  public static extern int CreateAppContainerProfile(
    [MarshalAs(UnmanagedType.LPWStr)] string pszAppContainerName,
    [MarshalAs(UnmanagedType.LPWStr)] string pszDisplayName,
    [MarshalAs(UnmanagedType.LPWStr)] string pszDescription,
    IntPtr pCapabilities, uint dwCapabilityCount, out IntPtr ppSidAppContainerSid);

  [DllImport("userenv.dll", SetLastError=true)]
  public static extern int DeleteAppContainerProfile(
    [MarshalAs(UnmanagedType.LPWStr)] string pszAppContainerName);

  [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
  public static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

  [StructLayout(LayoutKind.Sequential)]
  public struct SECURITY_CAPABILITIES {
    public IntPtr AppContainerSid;
    public IntPtr Capabilities;
    public uint CapabilityCount;
  }

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool InitializeProcThreadAttributeList(
    IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool UpdateProcThreadAttribute(
    IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute,
    IntPtr lpValue, IntPtr cbSize, IntPtr lpPrevValue, IntPtr lpReturnSize);
}
"@

function Say([string]$tag, $obj) { [Console]::Out.WriteLine(("DBG " + $tag + " " + ($obj | ConvertTo-Json -Compress))) }

$sid = [IntPtr]::Zero
$hr = [AcDbg]::CreateAppContainerProfile($ContainerName, $ContainerName, "dbg", [IntPtr]::Zero, 0, [ref]$sid)
Say "create" @{ hr = ("0x{0:X8}" -f $hr); ok = ($hr -eq 0) }
if ($hr -ne 0) { exit 10 }
try {
  $sidStr = [IntPtr]::Zero
  [void][AcDbg]::ConvertSidToStringSid($sid, [ref]$sidStr)
  $sidText = [Runtime.InteropServices.Marshal]::PtrToStringUni($sidStr)
  Say "sid" @{ sid = $sidText }

  $sizeViaType = [Runtime.InteropServices.Marshal]::SizeOf([type][AcDbg+SECURITY_CAPABILITIES])
  $sc = New-Object AcDbg+SECURITY_CAPABILITIES
  $sizeViaObj = [Runtime.InteropServices.Marshal]::SizeOf($sc)
  Say "sizes" @{ viaType = $sizeViaType; viaObject = $sizeViaObj }

  $attrSize = [IntPtr]::Zero
  [void][AcDbg]::InitializeProcThreadAttributeList([IntPtr]::Zero, 1, 0, [ref]$attrSize)
  Say "attr-size-required" @{ bytes = [int]$attrSize }
  $list = [Runtime.InteropServices.Marshal]::AllocHGlobal($attrSize)
  $okInit = [AcDbg]::InitializeProcThreadAttributeList($list, 1, 0, [ref]$attrSize)
  Say "init-list" @{ ok = $okInit; lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error(); sizeAfter = [int]$attrSize }
  if (-not $okInit) { exit 12 }

  # Allocate unmanaged memory for SECURITY_CAPABILITIES manually and update
  # via the pointer-flavored signature (avoids PowerShell ref-struct quirks).
  $ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($sizeViaType)
  try {
    [Runtime.InteropServices.Marshal]::WriteIntPtr($ptr, 0, $sid)
    $ptrSize = [Runtime.InteropServices.Marshal]::SizeOf([type][System.IntPtr])
    [Runtime.InteropServices.Marshal]::WriteIntPtr($ptr, $ptrSize, [IntPtr]::Zero)
    [Runtime.InteropServices.Marshal]::WriteInt32($ptr, 2 * $ptrSize, 0)
    foreach ($cb in @($sizeViaType, 20)) {
      $ok = [AcDbg]::UpdateProcThreadAttribute($list, 0, [IntPtr]0x00020013, $ptr, [IntPtr]$cb, [IntPtr]::Zero, [IntPtr]::Zero)
      $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      Say "update" @{ cbSize = $cb; ok = $ok; lastError = $err }
      if ($ok) { break }
    }
  } finally {
    [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
    [Runtime.InteropServices.Marshal]::FreeHGlobal($list)
  }
} finally {
  $hrDel = [AcDbg]::DeleteAppContainerProfile($ContainerName)
  Say "delete" @{ hr = ("0x{0:X8}" -f $hrDel); ok = ($hrDel -eq 0) }
}
