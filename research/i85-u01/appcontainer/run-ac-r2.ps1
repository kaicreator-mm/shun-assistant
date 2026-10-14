# i85-U01 R2 — launch the DeepSeek API inference child inside a real Windows
# AppContainer whose ONLY capability is internetClient (S-1-15-3-1), as a
# NON-ADMIN, via raw P/Invoke: CreateAppContainerProfile + CreateProcessW
# (EXTENDED_STARTUPINFO_EX + PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES with
# one capability SID). The child talks to the broker EXCLUSIVELY through
# restricted anonymous stdin/stdout/stderr pipes (no loopback, no named
# endpoints, no loopback exemption). Scope note: per user instruction the
# "model" is the remote DeepSeek API (deepseek-flash); offline local inference
# is NOT tested here and REAL_LOCAL_INFERENCE remains BLOCKED by definition.
# ALWAYS deletes the AppContainer profile in the finally block.
# The whole native launch sequence lives in C# (AcR2.LaunchInference): the
# attribute list only RECORDS the lpValue pointer, so every buffer must
# outlive UpdateProcThreadAttribute until CreateProcessW returns (R1 lesson:
# PowerShell [ref] marshaling of STARTUPINFOEX dangles the list -> error 87).
param(
  [Parameter(Mandatory=$true)][string]$NodeExe,
  [Parameter(Mandatory=$true)][string]$ChildScript,
  [Parameter(Mandatory=$true)][string]$StdinPayloadFile,
  [Parameter(Mandatory=$true)][string]$StdoutLog,
  [Parameter(Mandatory=$true)][string]$StderrLog,
  [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$LoopPort,
  [Parameter(Mandatory=$true)][string]$LanHost,
  [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$LanPort,
  [Parameter(Mandatory=$true)][string]$ContainerName,
  [Parameter(Mandatory=$true)][ValidateRange(1,600)][int]$WaitTimeoutSec
)

$ErrorActionPreference = 'Continue'
# Outputs must be fresh per run; the stdin payload is a deliberately prepared
# INPUT and must exist and be readable.
if (-not (Test-Path -LiteralPath $StdinPayloadFile -PathType Leaf)) {
  [Console]::Error.WriteLine("ACR2 preflight PAYLOAD_MISSING: $StdinPayloadFile")
  exit 18
}
foreach ($f in @($StdoutLog, $StderrLog)) {
  if (Test-Path -LiteralPath $f) {
    [Console]::Error.WriteLine("ACR2 preflight FILE_ALREADY_EXISTS: $f; use a fresh disposable directory")
    exit 17
  }
}

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class AcR2 {
  [DllImport("userenv.dll", SetLastError=true)]
  public static extern int CreateAppContainerProfile(
    [MarshalAs(UnmanagedType.LPWStr)] string pszAppContainerName,
    [MarshalAs(UnmanagedType.LPWStr)] string pszDisplayName,
    [MarshalAs(UnmanagedType.LPWStr)] string pszDescription,
    IntPtr pCapabilities,
    uint dwCapabilityCount,
    out IntPtr ppSidAppContainerSid);

  [DllImport("userenv.dll", SetLastError=true)]
  public static extern int DeleteAppContainerProfile(
    [MarshalAs(UnmanagedType.LPWStr)] string pszAppContainerName);

  [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
  public static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr LocalFree(IntPtr hMem);

  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern IntPtr FreeSid(IntPtr sid);

  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool AllocateAndInitializeSid(
    byte[] pIdentifierAuthority, byte nSubAuthorityCount,
    uint nSubAuthority0, uint nSubAuthority1, uint nSubAuthority2, uint nSubAuthority3,
    uint nSubAuthority4, uint nSubAuthority5, uint nSubAuthority6, uint nSubAuthority7,
    out IntPtr pSid);

  [StructLayout(LayoutKind.Sequential)]
  public struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

  // Derive the real capability SID for a capability name via ntdll (the
  // wrapper DeriveCapabilitySidsByName lives in an api-ms set the .NET
  // Framework loader cannot bind). Buffers are caller-allocated
  // SECURITY_MAX_SID_SIZE (68) and zero-initialized.
  [DllImport("ntdll.dll")]
  public static extern int RtlDeriveCapabilitySidsFromName(ref UNICODE_STRING name, IntPtr groupSid, IntPtr capSid);

  [StructLayout(LayoutKind.Sequential)]
  public struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }

  public static string SidText(IntPtr sid) {
    IntPtr s = IntPtr.Zero;
    if (!ConvertSidToStringSid(sid, out s)) return null;
    string t = Marshal.PtrToStringUni(s);
    LocalFree(s);
    return t;
  }

  public static int DeriveCapability(string name, out IntPtr capSid, out string capSidText, out IntPtr groupSid, out string groupSidText) {
    capSid = IntPtr.Zero; capSidText = null; groupSid = IntPtr.Zero; groupSidText = null;
    IntPtr nameBuf = Marshal.StringToHGlobalUni(name);
    try {
      UNICODE_STRING us = new UNICODE_STRING();
      us.Buffer = nameBuf;
      us.Length = (ushort)(name.Length * 2);
      us.MaximumLength = (ushort)(name.Length * 2 + 2);
      groupSid = Marshal.AllocHGlobal(68);
      capSid = Marshal.AllocHGlobal(68);
      for (int i = 0; i < 68; i++) { Marshal.WriteByte(groupSid, i, 0); Marshal.WriteByte(capSid, i, 0); }
      int st = RtlDeriveCapabilitySidsFromName(ref us, groupSid, capSid);
      if (st == 0) { groupSidText = SidText(groupSid); capSidText = SidText(capSid); }
      return st;
    } finally { Marshal.FreeHGlobal(nameBuf); }
  }

  // CreateAppContainerProfile must itself receive the capability list as
  // SID_AND_ATTRIBUTES; a capability-less profile plus a capability-bearing
  // SECURITY_CAPABILITIES attribute is rejected by CreateProcessW with
  // ERROR_INVALID_PARAMETER 87 (empirical bisect on build 26300).
  public static int CreateProfileWithCaps(string name, string d1, string d2,
      IntPtr[] capSidArr, out IntPtr sidOut) {
    IntPtr arr = IntPtr.Zero;
    try {
      uint cnt = (capSidArr == null) ? 0u : (uint)capSidArr.Length;
      if (cnt > 0) {
        arr = Marshal.AllocHGlobal((int)(cnt * 16));
        for (uint i = 0; i < cnt; i++) {
          Marshal.WriteIntPtr(arr, (int)(i * 16), capSidArr[i]);
          Marshal.WriteInt32(arr, (int)(i * 16 + IntPtr.Size), 4); // SE_GROUP_ENABLED
        }
      }
      return CreateAppContainerProfile(name, d1, d2, arr, cnt, out sidOut);
    } finally { if (arr != IntPtr.Zero) Marshal.FreeHGlobal(arr); }
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct SECURITY_ATTRIBUTES {
    public int nLength;
    public IntPtr lpSecurityDescriptor;
    public bool bInheritHandle;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct SECURITY_CAPABILITIES {
    public IntPtr AppContainerSid;
    public IntPtr Capabilities;
    public uint CapabilityCount;
    public uint Reserved;
  }

  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct STARTUPINFOEXW {
    public STARTUPINFOW StartupInfo;
    public IntPtr lpAttributeList;
  }

  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct STARTUPINFOW {
    public uint cb;
    public IntPtr lpReserved;
    public IntPtr lpDesktop;
    public IntPtr lpTitle;
    public uint dwX;
    public uint dwY;
    public uint dwXSize;
    public uint dwYSize;
    public uint dwXCountChars;
    public uint dwYCountChars;
    public uint dwFillAttribute;
    public uint dwFlags;
    public ushort wShowWindow;
    public ushort cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct PROCESS_INFORMATION {
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
  }

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool InitializeProcThreadAttributeList(
    IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool UpdateProcThreadAttribute(
    IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute,
    IntPtr lpValue, IntPtr cbSize, IntPtr lpPrevValue, IntPtr lpReturnSize);

  [DllImport("kernel32.dll")]
  public static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool CreateProcessW(
    string lpApplicationName,
    string lpCommandLine,
    IntPtr lpProcessAttributes,
    IntPtr lpThreadAttributes,
    bool bInheritHandles,
    uint dwCreationFlags,
    IntPtr lpEnvironment,
    string lpCurrentDirectory,
    ref STARTUPINFOEXW lpStartupInfo,
    out PROCESS_INFORMATION lpProcessInformation);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr hHandle);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe,
    ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite,
    out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToRead,
    out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool OpenProcessToken(IntPtr hProcess, uint access, out IntPtr hToken);

  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool GetTokenInformation(IntPtr hToken, int infoClass, IntPtr info, uint infoLen, out uint returnLen);

  public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
  public const uint STARTF_USESTDHANDLES = 0x00000100;
  public const uint HANDLE_FLAG_INHERIT = 0x00000002;
  public static readonly IntPtr PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = (IntPtr)0x00020009;
  // AppContainer (LowBox) creation rejects broad handle inheritance
  // (ERROR_INVALID_PARAMETER 87); the supported channel is an explicit
  // inheritable-handle list naming exactly the stdio pipe ends.
  public static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = (IntPtr)0x00020002;
  // TOKEN_INFORMATION_CLASS — empirically verified on build 26300 via
  // tokcaps-debug.ps1 (class scan + SID dump): 29=TokenIsAppContainer (ULONG),
  // 30=TokenCapabilities (TOKEN_GROUPS, S-1-15-3-1 at entry 0), 31=
  // TokenAppContainerSid (PSID, string-equal to the profile SID). Earlier
  // constants 28/29/5 were off (28=TokenLogonSid groups, 5=TokenPrimaryGroup).
  private const int TokenIsAppContainer = 29;
  private const int TokenAppContainerSid = 31;
  private const int TokenCapabilities = 30;

  private static string ReadPipeToEnd(IntPtr hRead) {
    List<byte> acc = new List<byte>();
    byte[] buf = new byte[4096];
    uint n = 0;
    while (ReadFile(hRead, buf, (uint)buf.Length, out n, IntPtr.Zero) && n > 0) {
      for (uint i = 0; i < n; i++) acc.Add(buf[i]);
    }
    return Encoding.UTF8.GetString(acc.ToArray());
  }

  private static List<string> TokenCapabilitySids(IntPtr hToken) {
    List<string> sids = new List<string>();
    uint need = 0;
    GetTokenInformation(hToken, TokenCapabilities, IntPtr.Zero, 0, out need);
    if (need < 12) return sids;
    IntPtr b = Marshal.AllocHGlobal((int)need);
    try {
      if (!GetTokenInformation(hToken, TokenCapabilities, b, need, out need)) return sids;
      uint count = (uint)Marshal.ReadInt32(b);
      // TOKEN_GROUPS on x64: DWORD GroupCount at 0 (padded), SID_AND_ATTRIBUTES
      // entries (IntPtr Sid + uint Attributes, 16-byte stride) start at offset 8.
      for (uint i = 0; i < count && i < 64; i++) {
        IntPtr sidp = Marshal.ReadIntPtr(b, 8 + (int)i * 16);
        if (sidp == IntPtr.Zero) continue;
        IntPtr s = IntPtr.Zero;
        if (ConvertSidToStringSid(sidp, out s)) {
          sids.Add(Marshal.PtrToStringUni(s));
          LocalFree(s);
        }
      }
    } finally { Marshal.FreeHGlobal(b); }
    return sids;
  }

  // Full native launch, kept inside C# so every buffer outlives exactly the
  // calls that dereference it. SECURITY_CAPABILITIES.Capabilities is an
  // SID_AND_ATTRIBUTES array (16-byte entries), matching the MS
  // LaunchAppContainer sample and Chromium sandbox; a bare PSID pointer array
  // is misparsed and CreateProcessW fails with ERROR_INVALID_PARAMETER 87.
  // rc: 0 ok; 1/2 attr-list init; 3 update-attr; 4 CreateProcessW; 5 stdin write;
  // 6 pipe create; 7 unexpected.
  public static int LaunchInference(string appName, string cmdLine, string workDir,
      IntPtr appContainerSid, IntPtr capabilitySid, byte[] stdinPayload, uint waitTimeoutMs,
      out int childPid, out int createError, out int waitResult, out uint childExitCode,
      out bool terminatedOnTimeout, out int isAppContainer, out string tokenSid,
      out string[] tokenCapabilities, out string childStdout, out string childStderr,
      out uint stdinBytesWritten) {
    childPid = 0; createError = 0; waitResult = -1; childExitCode = 0xFFFFFFFF;
    terminatedOnTimeout = false; isAppContainer = -1; tokenSid = null;
    tokenCapabilities = new string[0]; childStdout = null; childStderr = null;
    stdinBytesWritten = 0;

    IntPtr hStdinR = IntPtr.Zero, hStdinW = IntPtr.Zero;
    IntPtr hStdoutR = IntPtr.Zero, hStdoutW = IntPtr.Zero;
    IntPtr hStderrR = IntPtr.Zero, hStderrW = IntPtr.Zero;
    IntPtr attrList = IntPtr.Zero, scPtr = IntPtr.Zero, capArray = IntPtr.Zero,
            handleListPtr = IntPtr.Zero;
    IntPtr hProc = IntPtr.Zero, hThr = IntPtr.Zero;
    try {
      SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
      sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
      sa.lpSecurityDescriptor = IntPtr.Zero;
      sa.bInheritHandle = true; // child ends must be inheritable
      if (!CreatePipe(out hStdinR, out hStdinW, ref sa, 65536) ||
          !CreatePipe(out hStdoutR, out hStdoutW, ref sa, 65536) ||
          !CreatePipe(out hStderrR, out hStderrW, ref sa, 65536)) {
        createError = Marshal.GetLastWin32Error(); return 6;
      }
      // Parent ends must NOT be inheritable: the child inheriting the stdin
      // write end would break EOF semantics, and stray ends block pipe EOF.
      if (!SetHandleInformation(hStdinW, HANDLE_FLAG_INHERIT, 0) ||
          !SetHandleInformation(hStdoutR, HANDLE_FLAG_INHERIT, 0) ||
          !SetHandleInformation(hStderrR, HANDLE_FLAG_INHERIT, 0)) {
        createError = Marshal.GetLastWin32Error(); return 6;
      }

      IntPtr attrSize = IntPtr.Zero;
      // Size query: first call always returns FALSE with
      // ERROR_INSUFFICIENT_BUFFER (122) and fills attrSize — not an error.
      InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref attrSize);
      if (attrSize == IntPtr.Zero) { createError = Marshal.GetLastWin32Error(); return 1; }
      attrList = Marshal.AllocHGlobal(attrSize);
      if (!InitializeProcThreadAttributeList(attrList, 2, 0, ref attrSize)) {
        createError = Marshal.GetLastWin32Error(); return 2;
      }
      int scSize = Marshal.SizeOf(typeof(SECURITY_CAPABILITIES));
      scPtr = Marshal.AllocHGlobal(scSize);
      capArray = Marshal.AllocHGlobal(16);
      Marshal.WriteIntPtr(capArray, 0, capabilitySid);
      Marshal.WriteInt32(capArray, IntPtr.Size, 4); // SE_GROUP_ENABLED
      SECURITY_CAPABILITIES sc = new SECURITY_CAPABILITIES();
      sc.AppContainerSid = appContainerSid;
      sc.Capabilities = capArray;
      sc.CapabilityCount = 1;
      sc.Reserved = 0;
      Marshal.StructureToPtr(sc, scPtr, false);
      if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, scPtr,
          (IntPtr)scSize, IntPtr.Zero, IntPtr.Zero)) {
        createError = Marshal.GetLastWin32Error(); return 3;
      }
      handleListPtr = Marshal.AllocHGlobal(3 * IntPtr.Size);
      Marshal.WriteIntPtr(handleListPtr, 0 * IntPtr.Size, hStdinR);
      Marshal.WriteIntPtr(handleListPtr, 1 * IntPtr.Size, hStdoutW);
      Marshal.WriteIntPtr(handleListPtr, 2 * IntPtr.Size, hStderrW);
      if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handleListPtr,
          (IntPtr)(3 * IntPtr.Size), IntPtr.Zero, IntPtr.Zero)) {
        createError = Marshal.GetLastWin32Error(); return 3;
      }

      STARTUPINFOEXW si = new STARTUPINFOEXW();
      si.StartupInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOEXW));
      si.lpAttributeList = attrList;
      si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
      si.StartupInfo.hStdInput = hStdinR;
      si.StartupInfo.hStdOutput = hStdoutW;
      si.StartupInfo.hStdError = hStderrW;
      Console.WriteLine("ACR2C pre-createprocess");
      PROCESS_INFORMATION pi;
      if (!CreateProcessW(appName, cmdLine, IntPtr.Zero, IntPtr.Zero, true,
          EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, workDir, ref si, out pi)) {
        createError = Marshal.GetLastWin32Error(); return 4;
      }
      Console.WriteLine("ACR2C post-createprocess");
      hProc = pi.hProcess; hThr = pi.hThread;
      childPid = pi.dwProcessId;

      // The parent holds its own copies of the CHILD-end pipe handles from
      // CreatePipe; they must be dropped now or pipe EOF never arrives (the
      // parent itself would remain the last writer after the child exits).
      CloseHandle(hStdinR); hStdinR = IntPtr.Zero;
      CloseHandle(hStdoutW); hStdoutW = IntPtr.Zero;
      CloseHandle(hStderrW); hStderrW = IntPtr.Zero;

      // Token evidence via OS API, immediately while the child is alive.
      IntPtr hTok = IntPtr.Zero;
      if (OpenProcessToken(hProc, 0x0008, out hTok)) {
        uint need = 0;
        GetTokenInformation(hTok, TokenIsAppContainer, IntPtr.Zero, 0, out need);
        if (need >= 4) {
          IntPtr b = Marshal.AllocHGlobal((int)need);
          try { if (GetTokenInformation(hTok, TokenIsAppContainer, b, need, out need))
                  isAppContainer = Marshal.ReadInt32(b); }
          finally { Marshal.FreeHGlobal(b); }
        }
        uint need2 = 0;
        GetTokenInformation(hTok, TokenAppContainerSid, IntPtr.Zero, 0, out need2);
        if (need2 >= IntPtr.Size) {
          IntPtr b2 = Marshal.AllocHGlobal((int)need2);
          try {
            if (GetTokenInformation(hTok, TokenAppContainerSid, b2, need2, out need2)) {
              IntPtr sidp = Marshal.ReadIntPtr(b2);
              if (sidp != IntPtr.Zero) {
                IntPtr s = IntPtr.Zero;
                if (ConvertSidToStringSid(sidp, out s)) {
                  tokenSid = Marshal.PtrToStringUni(s);
                  LocalFree(s);
                }
              }
            }
          } finally { Marshal.FreeHGlobal(b2); }
        }
        tokenCapabilities = TokenCapabilitySids(hTok).ToArray();
        CloseHandle(hTok);
      }

      // Restricted stdin/stdout IPC: deliver the task payload, then EOF.
      Console.WriteLine("ACR2C pre-stdinwrite");
      if (!WriteFile(hStdinW, stdinPayload, (uint)stdinPayload.Length, out stdinBytesWritten, IntPtr.Zero) ||
          stdinBytesWritten != (uint)stdinPayload.Length) {
        createError = Marshal.GetLastWin32Error(); return 5;
      }
      CloseHandle(hStdinW); hStdinW = IntPtr.Zero;
      Console.WriteLine("ACR2C pre-wait");

      waitResult = (int)WaitForSingleObject(hProc, waitTimeoutMs);
      Console.WriteLine("ACR2C post-wait " + waitResult);
      if (waitResult == 258) {
        terminatedOnTimeout = TerminateProcess(hProc, 124);
        WaitForSingleObject(hProc, 5000);
      }
      GetExitCodeProcess(hProc, out childExitCode);

      // Child has exited; its write ends are gone, reads drain to EOF.
      Console.WriteLine("ACR2C pre-readout");
      childStdout = ReadPipeToEnd(hStdoutR);
      Console.WriteLine("ACR2C mid-readout");
      childStderr = ReadPipeToEnd(hStderrR);
      Console.WriteLine("ACR2C post-readout");
      return 0;
    } finally {
      if (hStdinR != IntPtr.Zero) CloseHandle(hStdinR);
      if (hStdinW != IntPtr.Zero) CloseHandle(hStdinW);
      if (hStdoutR != IntPtr.Zero) CloseHandle(hStdoutR);
      if (hStdoutW != IntPtr.Zero) CloseHandle(hStdoutW);
      if (hStderrR != IntPtr.Zero) CloseHandle(hStderrR);
      if (hStderrW != IntPtr.Zero) CloseHandle(hStderrW);
      if (attrList != IntPtr.Zero) { DeleteProcThreadAttributeList(attrList); Marshal.FreeHGlobal(attrList); }
      if (scPtr != IntPtr.Zero) Marshal.FreeHGlobal(scPtr);
      if (capArray != IntPtr.Zero) Marshal.FreeHGlobal(capArray);
      if (handleListPtr != IntPtr.Zero) Marshal.FreeHGlobal(handleListPtr);
      if (hProc != IntPtr.Zero) CloseHandle(hProc);
      if (hThr != IntPtr.Zero) CloseHandle(hThr);
    }
  }
}
"@

function Write-Stage([string]$stage, $payload) {
  [Console]::Out.WriteLine(("ACR2 " + $stage + " " + ($payload | ConvertTo-Json -Compress)))
}

$sid = [IntPtr]::Zero
$capSid = [IntPtr]::Zero
$grpSid = [IntPtr]::Zero
$profileCreated = $false
try {
  # Derive the internetClient capability SID first: CreateAppContainerProfile
  # must itself be created WITH the capability list, or CreateProcessW rejects
  # the capability-bearing SECURITY_CAPABILITIES with error 87 (empirical
  # bisect on build 26300; both grants together proven by debug-r2.ps1).
  $capSidText = $null; $grpSidText = $null
  $deriveSt = [AcR2]::DeriveCapability('internetClient', [ref]$capSid, [ref]$capSidText, [ref]$grpSid, [ref]$grpSidText)
  Write-Stage "capability-derived" @{ ntstatus = ("0x{0:X8}" -f $deriveSt); capSid = $capSidText; groupSid = $grpSidText; expected = 'S-1-15-3-1' }
  if ($deriveSt -ne 0 -or $capSidText -ne 'S-1-15-3-1') { exit 12 }

  $hr = [AcR2]::CreateProfileWithCaps($ContainerName, $ContainerName,
    "Shun i85-U01 R2 DeepSeek-API inference child (internetClient only)", @($capSid), [ref]$sid)
  Write-Stage "create-profile" @{ hr = ("0x{0:X8}" -f $hr); ok = ($hr -eq 0) }
  if ($hr -ne 0) { exit 10 }
  $profileCreated = $true

  $sidString = [IntPtr]::Zero
  if (-not [AcR2]::ConvertSidToStringSid($sid, [ref]$sidString)) {
    Write-Stage "sid-to-string" @{ ok = $false; lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    exit 11
  }
  $sidText = [Runtime.InteropServices.Marshal]::PtrToStringUni($sidString)
  [void][AcR2]::LocalFree($sidString)
  Write-Stage "container-sid" @{ sid = $sidText }

  # Grant the container SID modify on the stage directory and read+execute on
  # the staging tree; ALL APPLICATION PACKAGES gets RX so node.exe (copied
  # into the stage) can be mapped as an image.
  $stageDir = Split-Path -Parent $ChildScript
  $icaclsOut1 = & icacls.exe $stageDir /grant "*S-1-15-2-1:(OI)(CI)(RX)" 2>&1
  Write-Stage "icacls-all-app-packages" @{ rc = $LASTEXITCODE; out = ($icaclsOut1 -join ' | ') }
  if ($LASTEXITCODE -ne 0) { exit 19 }
  $icaclsOut2 = & icacls.exe $stageDir /grant ("*" + $sidText + ":(OI)(CI)(M)") 2>&1
  Write-Stage "icacls-container-sid" @{ rc = $LASTEXITCODE; out = ($icaclsOut2 -join ' | ') }
  if ($LASTEXITCODE -ne 0) { exit 20 }

  $payload = [System.IO.File]::ReadAllBytes($StdinPayloadFile)
  Write-Stage "stdin-payload" @{ bytes = $payload.Length }

  $cmdLine = '"' + $NodeExe + '" "' + $ChildScript + '" run ' + $LoopPort + ' "' + $LanHost + '" ' + $LanPort
  $childPid = 0; $createError = 0; $waitResult = -1; $childExitCode = [uint32]4294967295
  $terminated = $false; $isAppContainer = -1; $tokenSid = $null
  $tokenCaps = $null; $childStdout = $null; $childStderr = $null; [uint32]$stdinW = 0
  $rc = [AcR2]::LaunchInference($NodeExe, $cmdLine, $stageDir, $sid, $capSid, $payload,
    [uint32]($WaitTimeoutSec * 1000),
    [ref]$childPid, [ref]$createError, [ref]$waitResult, [ref]$childExitCode,
    [ref]$terminated, [ref]$isAppContainer, [ref]$tokenSid,
    [ref]$tokenCaps, [ref]$childStdout, [ref]$childStderr, [ref]$stdinW)
  Write-Stage "launch" @{ rc = $rc; createError = $createError; pid = $childPid; stdinBytesWritten = $stdinW }
  Write-Stage "child-token" @{ isAppContainer = $isAppContainer; appContainerSid = $tokenSid; capabilities = @($tokenCaps) }
  Write-Stage "child-exit" @{ wait = $waitResult; exitCode = $childExitCode; terminatedOnTimeout = $terminated }
  [System.IO.File]::WriteAllText($StdoutLog, [string]$childStdout)
  [System.IO.File]::WriteAllText($StderrLog, [string]$childStderr)
  Write-Stage "stdio-captured" @{ stdoutBytes = ([string]$childStdout).Length; stderrBytes = ([string]$childStderr).Length }
  if ($rc -ne 0) { exit 14 }
  # A launcher success is NOT proof of isolation or inference. Validate the
  # captured evidence strictly; anything missing or mismatched is non-PASS.
  if (($waitResult -ne 0) -or ($childExitCode -ne 0)) { exit 15 }
  if ($isAppContainer -ne 1) { Write-Stage "invalid-evidence" @{ reason = "child_token_not_appcontainer" }; exit 21 }
  if ($tokenSid -ne $sidText) { Write-Stage "invalid-evidence" @{ reason = "appcontainer_sid_mismatch" }; exit 21 }
  $caps = @($tokenCaps)
  $hasInternetClient = ($caps -contains 'S-1-15-3-1')
  $otherCaps = @($caps | Where-Object { $_ -like 'S-1-15-3-*' -and $_ -ne 'S-1-15-3-1' })
  if (-not $hasInternetClient -or $otherCaps.Count -gt 0) {
    Write-Stage "invalid-evidence" @{ reason = "unexpected_capability_set"; caps = $caps }; exit 21
  }
  try {
    $lines = @(([string]$childStdout) -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 } |
      ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
  } catch {
    Write-Stage "invalid-evidence" @{ reason = "stdout_not_jsonl" }; exit 21
  }
  $inferences = @($lines | Where-Object { $_.type -eq 'inference' })
  $summary = $lines | Where-Object { $_.type -eq 'summary' } | Select-Object -First 1
  if ($inferences.Count -lt 2) { Write-Stage "invalid-evidence" @{ reason = "fewer_than_two_inferences"; n = $inferences.Count }; exit 22 }
  for ($i = 0; $i -lt 2; $i++) {
    $inf = $inferences[$i]
    if ([int]$inf.seq -ne ($i + 1)) { Write-Stage "invalid-evidence" @{ reason = "seq_out_of_order" }; exit 22 }
    if ($inf.ok -ne $true) { Write-Stage "invalid-evidence" @{ reason = "inference_not_ok"; seq = $inf.seq; error = $inf.error }; exit 22 }
    if ($inf.modelEcho -ne 'deepseek-flash') { Write-Stage "invalid-evidence" @{ reason = "model_echo_mismatch"; seq = $inf.seq; echo = $inf.modelEcho }; exit 22 }
    if ([string]::IsNullOrWhiteSpace([string]$inf.contentExcerpt)) { Write-Stage "invalid-evidence" @{ reason = "empty_content"; seq = $inf.seq }; exit 22 }
    if (-not $inf.usage -or [int]$inf.usage.total_tokens -le 0) { Write-Stage "invalid-evidence" @{ reason = "missing_usage"; seq = $inf.seq }; exit 22 }
    if ([string]::IsNullOrWhiteSpace([string]$inf.peerCert.fingerprint256)) { Write-Stage "invalid-evidence" @{ reason = "missing_peer_cert"; seq = $inf.seq }; exit 22 }
  }
  if ($summary.probes.loopback.outcome -eq 'CONNECTED') { Write-Stage "invalid-evidence" @{ reason = "loopback_connected_isolation_fail" }; exit 22 }
  if ($summary.probes.lan.outcome -eq 'CONNECTED') { Write-Stage "invalid-evidence" @{ reason = "lan_connected_isolation_fail" }; exit 22 }
  Write-Stage "evidence-valid" @{ inferences = $inferences.Count; loopback = $summary.probes.loopback.outcome; lan = $summary.probes.lan.outcome; note = "Final verdict remains broker-side with independent observation" }
  exit 0
} finally {
  if ($profileCreated) {
    $hrDel = [AcR2]::DeleteAppContainerProfile($ContainerName)
    Write-Stage "delete-profile" @{ hr = ("0x{0:X8}" -f $hrDel); ok = ($hrDel -eq 0) }
  }
  if ($grpSid -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($grpSid) }
  if ($capSid -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($capSid) }
  if ($sid -ne [IntPtr]::Zero) { [void][AcR2]::FreeSid($sid) }
}
