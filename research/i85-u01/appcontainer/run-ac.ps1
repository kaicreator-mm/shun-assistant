# i85-U01 step 4b — launch a minimal node probe inside a real Windows
# AppContainer (no internet capability) as a NON-ADMIN, via raw P/Invoke:
# CreateAppContainerProfile + CreateProcessW(EXTENDED_STARTUPINFOEX +
# PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES). The child attempts a loopback
# connect and a TEST-NET-1 connect and writes JSON to OutFile.
# ALWAYS deletes the AppContainer profile in the finally block.
param(
  [Parameter(Mandatory=$true)][string]$NodeExe,
  [Parameter(Mandatory=$true)][string]$ChildScript,
  [Parameter(Mandatory=$true)][string]$OutFile,
  [Parameter(Mandatory=$true)][int]$LocalPort,
  [Parameter(Mandatory=$true)][string]$ContainerName
)

$ErrorActionPreference = 'Continue'

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

  [StructLayout(LayoutKind.Sequential)]
  public struct SECURITY_CAPABILITIES {
    public IntPtr AppContainerSid;
    public IntPtr Capabilities;
    public uint CapabilityCount;
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

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool InitializeProcThreadAttributeList(
    IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool UpdateProcThreadAttribute(
    IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute,
    ref SECURITY_CAPABILITIES lpValue, IntPtr cbSize, IntPtr lpPrevValue, IntPtr lpReturnSize);

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

  [StructLayout(LayoutKind.Sequential)]
  public struct PROCESS_INFORMATION {
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
  }

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr hHandle);

  public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
  public const uint INFINITE = 0xFFFFFFFF;
  public static readonly IntPtr PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = (IntPtr)0x00020013;
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
  $icaclsOut2 = & icacls.exe $stageDir /grant ("*" + $sidText + ":(OI)(CI)(M)") 2>&1
  Write-Stage "icacls-container-sid" @{ rc = $LASTEXITCODE; out = ($icaclsOut2 -join ' | ') }

  # Attribute list with one entry: SECURITY_CAPABILITIES (no capabilities).
  $attrSize = [IntPtr]::Zero
  [void][AcProbe]::InitializeProcThreadAttributeList([IntPtr]::Zero, 1, 0, [ref]$attrSize)
  $attrList = [Runtime.InteropServices.Marshal]::AllocHGlobal($attrSize)
  try {
    if (-not [AcProbe]::InitializeProcThreadAttributeList($attrList, 1, 0, [ref]$attrSize)) {
      Write-Stage "init-attr-list" @{ ok = $false; lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
      exit 12
    }
    $sc = New-Object AcProbe+SECURITY_CAPABILITIES
    $sc.AppContainerSid = $sid
    $sc.Capabilities = [IntPtr]::Zero
    $sc.CapabilityCount = 0
    if (-not [AcProbe]::UpdateProcThreadAttribute($attrList, 0, [AcProbe]::PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, [ref]$sc, [Runtime.InteropServices.Marshal]::SizeOf($sc), [IntPtr]::Zero, [IntPtr]::Zero)) {
      Write-Stage "update-attr" @{ ok = $false; lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
      exit 13
    }

    $si = New-Object AcProbe+STARTUPINFOEXW
    $si.StartupInfo = New-Object AcProbe+STARTUPINFOW
    $si.StartupInfo.cb = [Runtime.InteropServices.Marshal]::SizeOf($si)
    $si.lpAttributeList = $attrList
    $pi = New-Object AcProbe+PROCESS_INFORMATION

    $cmdLine = '"' + $NodeExe + '" "' + $ChildScript + '" ' + $LocalPort + ' "' + $OutFile + '"'
    $ok = [AcProbe]::CreateProcessW($NodeExe, $cmdLine, [IntPtr]::Zero, [IntPtr]::Zero, $false, [AcProbe]::EXTENDED_STARTUPINFO_PRESENT, [IntPtr]::Zero, $stageDir, [ref]$si, [ref]$pi)
    if (-not $ok) {
      Write-Stage "create-process" @{ ok = $false; lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
      exit 14
    }
    Write-Stage "create-process" @{ ok = $true; pid = $pi.dwProcessId }

    $wait = [AcProbe]::WaitForSingleObject($pi.hProcess, 60000)
    $exitCode = [uint32]4294967295
    [void][AcProbe]::GetExitCodeProcess($pi.hProcess, [ref]$exitCode)
    [void][AcProbe]::CloseHandle($pi.hThread)
    [void][AcProbe]::CloseHandle($pi.hProcess)
    Write-Stage "child-exit" @{ wait = $wait; exitCode = $exitCode }
  } finally {
    [Runtime.InteropServices.Marshal]::FreeHGlobal($attrList)
  }
  exit 0
} finally {
  if ($profileCreated) {
    $hrDel = [AcProbe]::DeleteAppContainerProfile($ContainerName)
    Write-Stage "delete-profile" @{ hr = ("0x{0:X8}" -f $hrDel); ok = ($hrDel -eq 0) }
  }
}
