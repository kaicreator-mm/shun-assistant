# i85-U01 step 4b debug round 2 — the ENTIRE attribute-list sequence runs in
# pure C# (no PowerShell struct marshaling anywhere). Also probes a second
# attribute type (PARENT_PROCESS) for comparison.
param([Parameter(Mandatory=$true)][string]$ContainerName)
$ErrorActionPreference = 'Continue'

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class AcDbg2 {
  [DllImport("userenv.dll", SetLastError=true)]
  public static extern int CreateAppContainerProfile(
    [MarshalAs(UnmanagedType.LPWStr)] string pszAppContainerName,
    [MarshalAs(UnmanagedType.LPWStr)] string pszDisplayName,
    [MarshalAs(UnmanagedType.LPWStr)] string pszDescription,
    IntPtr pCapabilities, uint dwCapabilityCount, out IntPtr ppSidAppContainerSid);

  [DllImport("userenv.dll", SetLastError=true)]
  public static extern int DeleteAppContainerProfile(
    [MarshalAs(UnmanagedType.LPWStr)] string pszAppContainerName);

  [StructLayout(LayoutKind.Sequential)]
  public struct SECURITY_CAPABILITIES {
    public IntPtr AppContainerSid;
    public IntPtr Capabilities;
    public uint CapabilityCount;
    public uint Reserved;
  }

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool InitializeProcThreadAttributeList(
    IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool UpdateProcThreadAttribute(
    IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute,
    IntPtr lpValue, IntPtr cbSize, IntPtr lpPrevValue, IntPtr lpReturnSize);

  public static string RunAll(IntPtr sidPtr) {
    StringBuilder sb = new StringBuilder();
    IntPtr size = IntPtr.Zero;
    InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
    sb.Append("reqSize=" + (int)size + ";");
    IntPtr list = Marshal.AllocHGlobal((int)size);
    bool init = InitializeProcThreadAttributeList(list, 1, 0, ref size);
    sb.Append("init=" + init + ";");
    if (!init) { sb.Append("initErr=" + Marshal.GetLastWin32Error() + ";"); return sb.ToString(); }

    int scSize = Marshal.SizeOf(typeof(SECURITY_CAPABILITIES));
    sb.Append("scSize=" + scSize + ";");
    SECURITY_CAPABILITIES sc = new SECURITY_CAPABILITIES();
    sc.AppContainerSid = sidPtr;
    sc.Capabilities = IntPtr.Zero;
    sc.CapabilityCount = 0;
    IntPtr pSc = Marshal.AllocHGlobal(scSize);
    Marshal.StructureToPtr(sc, pSc, false);

    // Attribute under test: SECURITY_CAPABILITIES (0x00020009).
    bool updSec = UpdateProcThreadAttribute(list, 0, (IntPtr)0x00020009, pSc, (IntPtr)scSize, IntPtr.Zero, IntPtr.Zero);
    sb.Append("upd_sec=" + updSec + ",err=" + Marshal.GetLastWin32Error() + ";");

    // Comparison attribute: PARENT_PROCESS with a NULL handle (value format
    // differs, so a failure there is only a call-mechanics control).
    IntPtr fakeHandle = Marshal.AllocHGlobal(IntPtr.Size);
    Marshal.WriteIntPtr(fakeHandle, IntPtr.Zero);
    bool updParent = UpdateProcThreadAttribute(list, 0, (IntPtr)0x00020000, fakeHandle, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
    sb.Append("upd_parent=" + updParent + ",err=" + Marshal.GetLastWin32Error() + ";");

    Marshal.FreeHGlobal(fakeHandle);
    Marshal.FreeHGlobal(pSc);
    Marshal.FreeHGlobal(list);
    return sb.ToString();
  }
}
"@

$sid = [IntPtr]::Zero
$hr = [AcDbg2]::CreateAppContainerProfile($ContainerName, $ContainerName, "dbg2", [IntPtr]::Zero, 0, [ref]$sid)
[Console]::Out.WriteLine(("DBG2 create hr=0x{0:X8} ok={1}" -f $hr, ($hr -eq 0)))
if ($hr -ne 0) { exit 10 }
try {
  $result = [AcDbg2]::RunAll($sid)
  [Console]::Out.WriteLine("DBG2 sequence $result")
} finally {
  $hrDel = [AcDbg2]::DeleteAppContainerProfile($ContainerName)
  $delOk = ($hrDel -eq 0)
  [Console]::Out.WriteLine(("DBG2 delete hr=0x{0:X8} ok={1}" -f $hrDel, $delOk))
}
