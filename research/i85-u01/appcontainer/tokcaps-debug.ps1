# i85-U01 R2 debug — dump TokenCapabilities (class 5) of a live capability'd
# AppContainer child, with the ENTIRE native sequence inside C# (R1 lesson:
# PowerShell [ref] marshaling of STARTUPINFOEX dangles the attribute list
# and CreateProcessW fails 87). No API use; child just sleeps 10s.
param(
  [Parameter(Mandatory=$true)][string]$NodeExe,
  [Parameter(Mandatory=$true)][string]$ContainerName
)
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class TcDbg2 {
  [DllImport("userenv.dll", SetLastError=true)]
  public static extern int CreateAppContainerProfile([MarshalAs(UnmanagedType.LPWStr)] string n,
    [MarshalAs(UnmanagedType.LPWStr)] string d1, [MarshalAs(UnmanagedType.LPWStr)] string d2,
    IntPtr caps, uint cnt, out IntPtr sid);
  [DllImport("userenv.dll", SetLastError=true)]
  public static extern int DeleteAppContainerProfile([MarshalAs(UnmanagedType.LPWStr)] string n);
  [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
  public static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr s);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr LocalFree(IntPtr h);
  [StructLayout(LayoutKind.Sequential)]
  public struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
  [DllImport("ntdll.dll")]
  public static extern int RtlDeriveCapabilitySidsFromName(ref UNICODE_STRING n, IntPtr g, IntPtr c);
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
  [DllImport("kernel32.dll")] public static extern void DeleteProcThreadAttributeList(IntPtr l);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern uint WaitForSingleObject(IntPtr h, uint ms);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool CreateProcessW(string app, string cmd, IntPtr pa, IntPtr ta,
    bool inh, uint cf, IntPtr env, string cwd, ref STARTUPINFOEXW si, out PROCESS_INFORMATION pi);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool OpenProcessToken(IntPtr h, uint a, out IntPtr t);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool GetTokenInformation(IntPtr t, int cls, IntPtr b, uint len, out uint need);
  public static readonly IntPtr ATTR_SEC_CAPS = (IntPtr)0x00020009;

  public static string SidText(IntPtr sid) {
    IntPtr s = IntPtr.Zero;
    if (!ConvertSidToStringSid(sid, out s)) return null;
    string t = Marshal.PtrToStringUni(s); LocalFree(s); return t;
  }

  public static void Run(string nodeExe, string containerName, string sleepMs) {
    IntPtr nameBuf = Marshal.StringToHGlobalUni("internetClient");
    IntPtr grp = Marshal.AllocHGlobal(68), cap = Marshal.AllocHGlobal(68);
    IntPtr capsArr = Marshal.AllocHGlobal(16);
    IntPtr sid = IntPtr.Zero;
    IntPtr attrList = IntPtr.Zero, scPtr = IntPtr.Zero;
    IntPtr hProc = IntPtr.Zero, hThr = IntPtr.Zero, hTok = IntPtr.Zero;
    bool profiled = false;
    try {
      UNICODE_STRING us = new UNICODE_STRING();
      us.Buffer = nameBuf; us.Length = 28; us.MaximumLength = 30;
      for (int i = 0; i < 68; i++) { Marshal.WriteByte(grp, i, 0); Marshal.WriteByte(cap, i, 0); }
      int st = RtlDeriveCapabilitySidsFromName(ref us, grp, cap);
      Console.WriteLine("derive st=0x" + st.ToString("X8") + " cap=" + SidText(cap));
      Marshal.WriteIntPtr(capsArr, 0, cap);
      Marshal.WriteInt32(capsArr, 8, 4);
      int hr = CreateAppContainerProfile(containerName, containerName, "tcdbg", capsArr, 1, out sid);
      Console.WriteLine("profile hr=" + hr);
      if (hr != 0) return;
      profiled = true;

      IntPtr attrSize = IntPtr.Zero;
      InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attrSize);
      attrList = Marshal.AllocHGlobal(attrSize);
      if (!InitializeProcThreadAttributeList(attrList, 1, 0, ref attrSize)) {
        Console.WriteLine("init-list err=" + Marshal.GetLastWin32Error()); return;
      }
      scPtr = Marshal.AllocHGlobal(24);
      SECURITY_CAPABILITIES sc = new SECURITY_CAPABILITIES();
      sc.AppContainerSid = sid; sc.Capabilities = capsArr; sc.CapabilityCount = 1; sc.Reserved = 0;
      Marshal.StructureToPtr(sc, scPtr, false);
      if (!UpdateProcThreadAttribute(attrList, 0, ATTR_SEC_CAPS, scPtr, (IntPtr)24, IntPtr.Zero, IntPtr.Zero)) {
        Console.WriteLine("update-attr err=" + Marshal.GetLastWin32Error()); return;
      }
      STARTUPINFOEXW si = new STARTUPINFOEXW();
      si.StartupInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOEXW));
      si.lpAttributeList = attrList;
      string cmd = "\"" + nodeExe + "\" -e \"setTimeout(()=>{}," + sleepMs + ")\"";
      PROCESS_INFORMATION pi;
      if (!CreateProcessW(nodeExe, cmd, IntPtr.Zero, IntPtr.Zero, false, 0x00080000,
          IntPtr.Zero, System.IO.Path.GetDirectoryName(nodeExe), ref si, out pi)) {
        Console.WriteLine("createprocess err=" + Marshal.GetLastWin32Error()); return;
      }
      hProc = pi.hProcess; hThr = pi.hThread;
      Console.WriteLine("launched pid=" + pi.dwProcessId);
      System.Threading.Thread.Sleep(1500);
      if (OpenProcessToken(hProc, 8, out hTok)) {
        foreach (int cls in new int[] { 24, 25, 26, 27, 28, 29, 30, 31, 32, 33 }) {
          uint need = 0;
          GetTokenInformation(hTok, cls, IntPtr.Zero, 0, out need);
          Console.WriteLine("class " + cls + " need=" + need);
          if (need >= 24 && need <= 4096 && (need % 8 == 0 || need % 8 == 4)) {
            IntPtr b = Marshal.AllocHGlobal((int)need);
            uint n2 = 0;
            if (GetTokenInformation(hTok, cls, b, need, out n2)) {
              var sb = new System.Text.StringBuilder();
              for (int i = 0; i < Math.Min(48, (int)need); i++) sb.Append(Marshal.ReadByte(b, i).ToString("X2")).Append(" ");
              Console.WriteLine("  hex48: " + sb.ToString());
              int cnt = Marshal.ReadInt32(b, 0);
              Console.WriteLine("  countIfGroups=" + cnt);
              foreach (int off in new int[] { 8, 4 }) {
                for (int i = 0; i < Math.Min(Math.Max(cnt, 0), 8); i++) {
                  IntPtr p = Marshal.ReadIntPtr(b, off + i * 16);
                  if (p != IntPtr.Zero) Console.WriteLine("  off" + off + " #" + i + " sid=" + SidText(p));
                }
              }
            }
            Marshal.FreeHGlobal(b);
          }
        }
        CloseHandle(hTok); hTok = IntPtr.Zero;
      } else Console.WriteLine("OpenProcessToken err=" + Marshal.GetLastWin32Error());
      WaitForSingleObject(hProc, 20000);
      CloseHandle(hProc); hProc = IntPtr.Zero;
      CloseHandle(hThr); hThr = IntPtr.Zero;
    } finally {
      if (hTok != IntPtr.Zero) CloseHandle(hTok);
      if (hProc != IntPtr.Zero) CloseHandle(hProc);
      if (hThr != IntPtr.Zero) CloseHandle(hThr);
      if (attrList != IntPtr.Zero) { DeleteProcThreadAttributeList(attrList); Marshal.FreeHGlobal(attrList); }
      if (scPtr != IntPtr.Zero) Marshal.FreeHGlobal(scPtr);
      if (profiled) { int d = DeleteAppContainerProfile(containerName); Console.WriteLine("delete-profile hr=" + d); }
      Marshal.FreeHGlobal(capsArr);
      Marshal.FreeHGlobal(grp); Marshal.FreeHGlobal(cap); Marshal.FreeHGlobal(nameBuf);
    }
  }
}
"@
[TcDbg2]::Run($NodeExe, $ContainerName, '10000')
