# i85-U01 step 4b — launch a minimal node probe inside a real Windows
# AppContainer (no internet capability) as a NON-ADMIN, via raw P/Invoke:
# CreateAppContainerProfile + CreateProcessW(EXTENDED_STARTUPINFOEX +
# PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES). The child attempts a loopback
# connect and a user-selected reachable controlled sink; no network PASS inference.
# ALWAYS deletes the AppContainer profile in the finally block.
# The whole native launch sequence lives in C# (AcProbe.LaunchProbe): the
# attribute list only RECORDS the lpValue pointer, so the SECURITY_CAPABILITIES
# buffer must outlive UpdateProcThreadAttribute until CreateProcessW returns,
# and PowerShell-side [ref] marshaling of the big STARTUPINFOEX cannot be
# trusted across those calls (both produced ERROR_INVALID_PARAMETER 87).
param(
  [Parameter(Mandatory=$true)][string]$NodeExe,
  [Parameter(Mandatory=$true)][string]$ChildScript,
  [Parameter(Mandatory=$true)][string]$OutFile,
  [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$LocalPort,
  [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$')][string]$ControlHost,
  [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$ControlPort,
  [Parameter(Mandatory=$true)][string]$ContainerName
)

$ErrorActionPreference = 'Continue'
# Each run must write fresh output. Stale result files cannot satisfy the probe.
if (Test-Path -LiteralPath $OutFile) {
  [Console]::Error.WriteLine('ACPROBE preflight OUTFILE_ALREADY_EXISTS; use a fresh disposable directory')
  exit 17
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class AcProbe {
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

  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool OpenProcessToken(IntPtr hProcess, uint access, out IntPtr hToken);

  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool GetTokenInformation(IntPtr hToken, int infoClass, IntPtr info, uint infoLen, out uint returnLen);

  public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
  public static readonly IntPtr PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = (IntPtr)0x00020009;
  private const int TokenIsAppContainer = 29;
  private const int TokenAppContainerSid = 31;

  // Full native launch, kept inside C# so every buffer outlives exactly the
  // calls that dereference it. rc: 0 ok; 1/2 attr-list init; 3 update-attr
  // (createError set); 4 CreateProcessW (createError set); 5 unexpected.
  public static int LaunchProbe(string appName, string cmdLine, string workDir, IntPtr appContainerSid,
      out int childPid, out int createError, out int waitResult, out uint childExitCode,
      out bool terminatedOnTimeout, out int isAppContainer, out string tokenSid) {
    childPid = 0; createError = 0; waitResult = -1; childExitCode = 0xFFFFFFFF;
    terminatedOnTimeout = false; isAppContainer = -1; tokenSid = null;

    IntPtr attrSize = IntPtr.Zero;
    // Size query: this first call always returns FALSE with
    // ERROR_INSUFFICIENT_BUFFER (122) and fills attrSize — not an error.
    InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attrSize);
    if (attrSize == IntPtr.Zero) {
      createError = Marshal.GetLastWin32Error(); return 1;
    }
    IntPtr attrList = Marshal.AllocHGlobal(attrSize);
    try {
      if (!InitializeProcThreadAttributeList(attrList, 1, 0, ref attrSize)) {
        createError = Marshal.GetLastWin32Error(); return 2;
      }
      int scSize = Marshal.SizeOf(typeof(SECURITY_CAPABILITIES));
      IntPtr scPtr = Marshal.AllocHGlobal(scSize);
      try {
        SECURITY_CAPABILITIES sc = new SECURITY_CAPABILITIES();
        sc.AppContainerSid = appContainerSid;
        sc.Capabilities = IntPtr.Zero;
        sc.CapabilityCount = 0;
        sc.Reserved = 0;
        Marshal.StructureToPtr(sc, scPtr, false);
        if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, scPtr,
            (IntPtr)scSize, IntPtr.Zero, IntPtr.Zero)) {
          createError = Marshal.GetLastWin32Error(); return 3;
        }

        STARTUPINFOEXW si = new STARTUPINFOEXW();
        si.StartupInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOEXW));
        si.lpAttributeList = attrList;
        PROCESS_INFORMATION pi;
        if (!CreateProcessW(appName, cmdLine, IntPtr.Zero, IntPtr.Zero, false,
            EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, workDir, ref si, out pi)) {
          createError = Marshal.GetLastWin32Error(); return 4;
        }
        try {
          childPid = pi.dwProcessId;

          // Token evidence via OS API, immediately while the child is alive.
          IntPtr hTok = IntPtr.Zero;
          if (OpenProcessToken(pi.hProcess, 0x0008, out hTok)) {
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
            CloseHandle(hTok);
          }

          waitResult = (int)WaitForSingleObject(pi.hProcess, 60000);
          if (waitResult == 258) {
            terminatedOnTimeout = TerminateProcess(pi.hProcess, 124);
            WaitForSingleObject(pi.hProcess, 5000);
          }
          GetExitCodeProcess(pi.hProcess, out childExitCode);
          return 0;
        } finally {
          CloseHandle(pi.hThread);
          CloseHandle(pi.hProcess);
        }
      } finally { Marshal.FreeHGlobal(scPtr); }
    } finally {
      DeleteProcThreadAttributeList(attrList);
      Marshal.FreeHGlobal(attrList);
    }
  }
}
"@

function Write-Stage([string]$stage, $payload) {
  [Console]::Out.WriteLine(("ACPROBE " + $stage + " " + ($payload | ConvertTo-Json -Compress)))
}

$sid = [IntPtr]::Zero
$profileCreated = $false
try {
  $hr = [AcProbe]::CreateAppContainerProfile($ContainerName, $ContainerName, "Shun i85-U01 network isolation probe (no capabilities)", [IntPtr]::Zero, 0, [ref]$sid)
  Write-Stage "create-profile" @{ hr = ("0x{0:X8}" -f $hr); ok = ($hr -eq 0) }
  if ($hr -ne 0) { exit 10 }
  $profileCreated = $true

  $sidString = [IntPtr]::Zero
  $sidText = $null
  if (-not [AcProbe]::ConvertSidToStringSid($sid, [ref]$sidString)) {
    Write-Stage "sid-to-string" @{ ok = $false; lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    exit 11
  }
  $sidText = [Runtime.InteropServices.Marshal]::PtrToStringUni($sidString)
  [void][AcProbe]::LocalFree($sidString)
  Write-Stage "container-sid" @{ sid = $sidText }

  # Grant the container SID modify on its probe output directory and read+
  # execute on the staging tree; ALL APPLICATION PACKAGES gets RX so node.exe
  # (copied into the stage) can be mapped as an image.
  $stageDir = Split-Path -Parent $ChildScript
  $icaclsOut1 = & icacls.exe $stageDir /grant "*S-1-15-2-1:(OI)(CI)(RX)" 2>&1
  Write-Stage "icacls-all-app-packages" @{ rc = $LASTEXITCODE; out = ($icaclsOut1 -join ' | ') }
  if ($LASTEXITCODE -ne 0) { exit 19 }
  $icaclsOut2 = & icacls.exe $stageDir /grant ("*" + $sidText + ":(OI)(CI)(M)") 2>&1
  Write-Stage "icacls-container-sid" @{ rc = $LASTEXITCODE; out = ($icaclsOut2 -join ' | ') }
  if ($LASTEXITCODE -ne 0) { exit 20 }

  $cmdLine = '"' + $NodeExe + '" "' + $ChildScript + '" ' + $LocalPort + ' "' + $OutFile + '" "' + $ControlHost + '" ' + $ControlPort
  $childPid = 0; $createError = 0; $waitResult = -1; $childExitCode = [uint32]4294967295
  $terminated = $false; $isAppContainer = -1; $tokenSid = $null
  $rc = [AcProbe]::LaunchProbe($NodeExe, $cmdLine, $stageDir, $sid,
    [ref]$childPid, [ref]$createError, [ref]$waitResult, [ref]$childExitCode,
    [ref]$terminated, [ref]$isAppContainer, [ref]$tokenSid)
  Write-Stage "launch" @{ rc = $rc; createError = $createError; pid = $childPid }
  Write-Stage "child-token" @{ isAppContainer = $isAppContainer; appContainerSid = $tokenSid; tokenObserved = ($isAppContainer -ge 0) }
  Write-Stage "child-exit" @{ wait = $waitResult; exitCode = $childExitCode; terminatedOnTimeout = $terminated }
  if ($rc -ne 0) { exit 14 }
  # A launcher success is NOT proof that the child ran, completed or observed
  # network controls. Missing/failed output is strictly non-PASS.
  if (($waitResult -ne 0) -or ($childExitCode -ne 0)) { exit 15 }
  if (-not (Test-Path -LiteralPath $OutFile -PathType Leaf)) { exit 16 }
  try {
    $probe = Get-Content -LiteralPath $OutFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($probe.fatal -or -not $probe.loopback -or -not $probe.controlled -or
        $probe.controlled.host -ne $ControlHost -or
        [int]$probe.controlled.port -ne $ControlPort -or
        $probe.controlled.outcome -notin @('CONNECTED','ERROR','TIMEOUT')) {
      Write-Stage "invalid-evidence" @{ ok = $false; reason = "missing_or_mismatched_probe" }
      exit 21
    }
    Write-Stage "probe-written" @{ ok = $true; controlledOutcome = $probe.controlled.outcome; note = "No automatic OS no-egress PASS from this record" }
  } catch {
    Write-Stage "invalid-evidence" @{ ok = $false; reason = "invalid_json_or_missing_fields" }
    exit 21
  }
  exit 0
} finally {
  if ($profileCreated) {
    $hrDel = [AcProbe]::DeleteAppContainerProfile($ContainerName)
    Write-Stage "delete-profile" @{ hr = ("0x{0:X8}" -f $hrDel); ok = ($hrDel -eq 0) }
  }
  if ($sid -ne [IntPtr]::Zero) { [void][AcProbe]::FreeSid($sid) }
}
