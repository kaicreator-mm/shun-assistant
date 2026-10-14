param([Parameter(Mandatory=$true)][string]$ContainerName)
$ErrorActionPreference = 'Continue'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class AcDbg3 {
  [DllImport("userenv.dll", SetLastError=true)]
  public static extern int CreateAppContainerProfile([MarshalAs(UnmanagedType.LPWStr)] string n, [MarshalAs(UnmanagedType.LPWStr)] string d, [MarshalAs(UnmanagedType.LPWStr)] string ds, IntPtr c, uint cc, out IntPtr sid);
  [DllImport("userenv.dll", SetLastError=true)]
  public static extern int DeleteAppContainerProfile([MarshalAs(UnmanagedType.LPWStr)] string n);
  [StructLayout(LayoutKind.Sequential)]
  public struct SECURITY_CAPABILITIES { public IntPtr AppContainerSid; public IntPtr Capabilities; public uint CapabilityCount; }
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool InitializeProcThreadAttributeList(IntPtr l, int c, int f, ref IntPtr s);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool UpdateProcThreadAttribute(IntPtr l, uint f, IntPtr a, IntPtr v, IntPtr s, IntPtr p, IntPtr r);
  public static string Sweep(IntPtr sidPtr) {
    StringBuilder sb = new StringBuilder();
    IntPtr size = IntPtr.Zero;
    InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
    IntPtr list = Marshal.AllocHGlobal((int)size);
    bool init = InitializeProcThreadAttributeList(list, 1, 0, ref size);
    sb.Append("init=" + init + ";");
    foreach (int cb in new int[] { 24, 28, 32, 40, 48 }) {
      SECURITY_CAPABILITIES sc = new SECURITY_CAPABILITIES();
      sc.AppContainerSid = sidPtr; sc.Capabilities = IntPtr.Zero; sc.CapabilityCount = 0;
      IntPtr p = Marshal.AllocHGlobal(cb);
      Marshal.StructureToPtr(sc, p, false);
      bool ok = UpdateProcThreadAttribute(list, 0, (IntPtr)0x00020013, p, (IntPtr)cb, IntPtr.Zero, IntPtr.Zero);
      sb.Append("cb=" + cb + ":ok=" + ok + ",err=" + Marshal.GetLastWin32Error() + ";");
      Marshal.FreeHGlobal(p);
    }
    Marshal.FreeHGlobal(list);
    return sb.ToString();
  }
}
"@
$sid = [IntPtr]::Zero
$hr = [AcDbg3]::CreateAppContainerProfile($ContainerName, $ContainerName, "dbg3", [IntPtr]::Zero, 0, [ref]$sid)
Write-Output ("DBG3 create hr=0x{0:X8}" -f $hr)
if ($hr -ne 0) { exit 10 }
try {
  Write-Output ("DBG3 sweep " + [AcDbg3]::Sweep($sid))
} finally {
  $hrDel = [AcDbg3]::DeleteAppContainerProfile($ContainerName)
  Write-Output ("DBG3 delete hr=0x{0:X8}" -f $hrDel)
}
