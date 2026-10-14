# i85-U01 R2 debug bisect — isolate which launcher delta breaks CreateProcessW
# (error 87): the capability array vs stdio/inherit. Config A: caps enabled,
# no stdio, no handle inheritance (R1-proven shape otherwise).
param(
  [Parameter(Mandatory=$true)][string]$NodeExe,
  [Parameter(Mandatory=$true)][string]$ChildScript,
  [Parameter(Mandatory=$true)][string]$ContainerName,
  [string]$Mode = 'A'
)
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class AcDbg {
  [DllImport("userenv.dll", SetLastError=true)]
  public static extern int CreateAppContainerProfile(
    [MarshalAs(UnmanagedType.LPWStr)] string n, [MarshalAs(UnmanagedType.LPWStr)] string d1,
    [MarshalAs(UnmanagedType.LPWStr)] string d2, IntPtr caps, uint cnt, out IntPtr sid);
  [DllImport("userenv.dll", SetLastError=true)]
  public static extern int DeleteAppContainerProfile([MarshalAs(UnmanagedType.LPWStr)] string n);
  [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
  public static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr s);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr LocalFree(IntPtr h);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern IntPtr FreeSid(IntPtr sid);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool AllocateAndInitializeSid(byte[] a, byte n, uint s0, uint s1,
    uint s2, uint s3, uint s4, uint s5, uint s6, uint s7, out IntPtr sid);
  [StructLayout(LayoutKind.Sequential)]
  public struct SECURITY_CAPABILITIES { public IntPtr AppContainerSid; public IntPtr Capabilities; public uint CapabilityCount; public uint Reserved; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct STARTUPINFOEXW { public STARTUPINFOW StartupInfo; public IntPtr lpAttributeList; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct STARTUPINFOW {
    public uint cb; public IntPtr lpReserved; public IntPtr lpDesktop; public IntPtr lpTitle;
    public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize;
    public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute;
    public uint dwFlags; public ushort wShowWindow; public ushort cbReserved2;
    public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool InitializeProcThreadAttributeList(IntPtr l, int c, int f, ref IntPtr sz);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool UpdateProcThreadAttribute(IntPtr l, uint f, IntPtr a, IntPtr v, IntPtr cb, IntPtr p, IntPtr r);
  [DllImport("kernel32.dll")]
  public static extern void DeleteProcThreadAttributeList(IntPtr l);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern uint WaitForSingleObject(IntPtr h, uint ms);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool GetExitCodeProcess(IntPtr h, out uint c);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool CreateProcessW(string app, string cmd, IntPtr pa, IntPtr ta,
    bool inh, uint cf, IntPtr env, string cwd, ref STARTUPINFOEXW si, out PROCESS_INFORMATION pi);
  public static readonly IntPtr ATTR_SEC_CAPS = (IntPtr)0x00020009;

  [DllImport("api-ms-win-security-capabilities-l1-1-0.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="DeriveCapabilitySidsFromName")]
  public static extern bool DeriveCapabilitySidsByName(string name,
    out IntPtr groupSids, out uint groupCount, out IntPtr capSids, out uint capCount);

  [StructLayout(LayoutKind.Sequential)]
  public struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

  // ntdyll-internal derivation used by DeriveCapabilitySidsByName; the .NET
  // Framework loader cannot bind the api-ms-win-security-capabilities set,
  // so derive via ntdll with caller-allocated SECURITY_MAX_SID_SIZE buffers.
  [DllImport("ntdll.dll")]
  public static extern int RtlDeriveCapabilitySidsFromName(ref UNICODE_STRING name, IntPtr groupSid, IntPtr capSid);

  public static string SidText(IntPtr sid) {
    IntPtr s = IntPtr.Zero;
    if (!ConvertSidToStringSid(sid, out s)) return null;
    string t = Marshal.PtrToStringUni(s);
    LocalFree(s);
    return t;
  }

  public static string[] PrintSids(IntPtr arr, uint n) {
    string[] r = new string[n];
    for (uint i = 0; i < n; i++) {
      IntPtr sidp = Marshal.ReadIntPtr(arr, (int)(i * IntPtr.Size));
      IntPtr s = IntPtr.Zero;
      if (ConvertSidToStringSid(sidp, out s)) { r[i] = Marshal.PtrToStringUni(s); LocalFree(s); }
    }
    return r;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }

  public static int CreateProfileWithCaps(string name, string d1, string d2,
      IntPtr[] capSidArr, out IntPtr sidOut) {
    IntPtr arr = IntPtr.Zero;
    try {
      uint cnt = (capSidArr == null) ? 0u : (uint)capSidArr.Length;
      if (cnt > 0) {
        arr = Marshal.AllocHGlobal((int)(cnt * 16));
        for (uint i = 0; i < cnt; i++) {
          Marshal.WriteIntPtr(arr, (int)(i * 16), capSidArr[i]);
          Marshal.WriteInt32(arr, (int)(i * 16 + IntPtr.Size), 4);
        }
      }
      return CreateAppContainerProfile(name, d1, d2, arr, cnt, out sidOut);
    } finally { if (arr != IntPtr.Zero) Marshal.FreeHGlobal(arr); }
  }

  public static string Launch(string appName, string cmdLine, string workDir, IntPtr acSid,
      IntPtr[] capSidArr, out int pid, out int createError, out uint exitCode) {
    pid = 0; createError = 0; exitCode = 0xFFFFFFFF;
    IntPtr attrSize = IntPtr.Zero;
    InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attrSize);
    IntPtr attrList = Marshal.AllocHGlobal(attrSize);
    IntPtr scPtr = IntPtr.Zero, capArray = IntPtr.Zero;
    IntPtr hProc = IntPtr.Zero, hThr = IntPtr.Zero;
    try {
      if (!InitializeProcThreadAttributeList(attrList, 1, 0, ref attrSize)) { createError = Marshal.GetLastWin32Error(); return "init-list"; }
      int scSize = Marshal.SizeOf(typeof(SECURITY_CAPABILITIES));
      scPtr = Marshal.AllocHGlobal(scSize);
      uint cnt = (capSidArr == null) ? 0u : (uint)capSidArr.Length;
      // SECURITY_CAPABILITIES.Capabilities is an array of SID_AND_ATTRIBUTES
      // {PSID Sid; DWORD Attributes} (MS LaunchAppContainer sample + Chromium
      // sandbox both pass SID_AND_ATTRIBUTES; a bare PSID array is misread and
      // CreateProcessW fails with ERROR_INVALID_PARAMETER 87).
      const uint SE_GROUP_ENABLED = 4;
      if (cnt > 0) {
        capArray = Marshal.AllocHGlobal((int)(cnt * 16));
        for (uint i = 0; i < cnt; i++) {
          Marshal.WriteIntPtr(capArray, (int)(i * 16), capSidArr[i]);
          Marshal.WriteInt32(capArray, (int)(i * 16 + IntPtr.Size), (int)SE_GROUP_ENABLED);
        }
      }
      SECURITY_CAPABILITIES sc = new SECURITY_CAPABILITIES();
      sc.AppContainerSid = acSid;
      sc.Capabilities = capArray;
      sc.CapabilityCount = cnt;
      sc.Reserved = 0;
      Marshal.StructureToPtr(sc, scPtr, false);
      if (!UpdateProcThreadAttribute(attrList, 0, ATTR_SEC_CAPS, scPtr, (IntPtr)scSize, IntPtr.Zero, IntPtr.Zero)) {
        createError = Marshal.GetLastWin32Error(); return "update-attr";
      }
      STARTUPINFOEXW si = new STARTUPINFOEXW();
      si.StartupInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOEXW));
      si.lpAttributeList = attrList;
      PROCESS_INFORMATION pi;
      if (!CreateProcessW(appName, cmdLine, IntPtr.Zero, IntPtr.Zero, false, 0x00080000,
          IntPtr.Zero, workDir, ref si, out pi)) {
        createError = Marshal.GetLastWin32Error(); return "createprocess";
      }
      hProc = pi.hProcess; hThr = pi.hThread; pid = pi.dwProcessId;
      WaitForSingleObject(hProc, 30000);
      GetExitCodeProcess(hProc, out exitCode);
      return "ok";
    } finally {
      if (hProc != IntPtr.Zero) CloseHandle(hProc);
      if (hThr != IntPtr.Zero) CloseHandle(hThr);
      if (attrList != IntPtr.Zero) { DeleteProcThreadAttributeList(attrList); Marshal.FreeHGlobal(attrList); }
      if (scPtr != IntPtr.Zero) Marshal.FreeHGlobal(scPtr);
      if (capArray != IntPtr.Zero) Marshal.FreeHGlobal(capArray);
    }
  }
}
"@
$useCaps = ($Mode -ne 'nocaps')
$preCapSids = $null
if ($useCaps -and $Mode -eq 'derive') {
  # derive first so the profile itself can be created WITH the capability
  $nameBuf = [Runtime.InteropServices.Marshal]::StringToHGlobalUni('internetClient')
  $us = New-Object AcDbg+UNICODE_STRING
  $us.Buffer = $nameBuf
  $us.Length = [uint16]('internetClient'.Length * 2)
  $us.MaximumLength = [uint16]('internetClient'.Length * 2 + 2)
  $g1 = [Runtime.InteropServices.Marshal]::AllocHGlobal(68)
  $g2 = [Runtime.InteropServices.Marshal]::AllocHGlobal(68)
  for ($i = 0; $i -lt 68; $i++) {
    [Runtime.InteropServices.Marshal]::WriteByte($g1, $i, 0)
    [Runtime.InteropServices.Marshal]::WriteByte($g2, $i, 0)
  }
  $st = [AcDbg]::RtlDeriveCapabilitySidsFromName([ref]$us, $g1, $g2)
  Write-Output ("rtl derive ntstatus=" + ('0x{0:X8}' -f $st) + " arg2=" + [AcDbg]::SidText($g1) + " arg3=" + [AcDbg]::SidText($g2))
  $preCapSids = @($g2)
}
$sid = [IntPtr]::Zero
if ($preCapSids) {
  $hr = [AcDbg]::CreateProfileWithCaps($ContainerName, $ContainerName, "dbg", $preCapSids, [ref]$sid)
} else {
  $hr = [AcDbg]::CreateAppContainerProfile($ContainerName, $ContainerName, "dbg", [IntPtr]::Zero, 0, [ref]$sid)
}
Write-Output ("profile hr=" + $hr)
$capSids = $null
$freeList = @()
if ($useCaps) {
  if ($Mode -eq 'derive') {
    $capSids = $preCapSids
  } else {
    $capSid = [IntPtr]::Zero
    $null = [AcDbg]::AllocateAndInitializeSid([byte[]](0,0,0,0,0,15), 2, 3, 1, 0, 0, 0, 0, 0, 0, [ref]$capSid)
    $capSids = @($capSid)
    $freeList = @()
  }
}
$pid2 = 0; $ce = 0; $ec = [uint32]0
$cmd = '"' + $NodeExe + '" -e "console.log(42)"'
$r = [AcDbg]::Launch($NodeExe, $cmd, (Split-Path -Parent $NodeExe), $sid, $capSids, [ref]$pid2, [ref]$ce, [ref]$ec)
Write-Output ("result=" + $r + " createError=" + $ce + " pid=" + $pid2 + " exit=" + $ec)
[void][AcDbg]::DeleteAppContainerProfile($ContainerName)
foreach ($f in $freeList) { if ($f -ne [IntPtr]::Zero) { [void][AcDbg]::LocalFree($f) } }
if ($sid -ne [IntPtr]::Zero) { [void][AcDbg]::FreeSid($sid) }
