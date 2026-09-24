<#
================================================================================
 enum_comcon_device_acl.ps1
 Engagement : APEX-5.6.1.4 (Hologic Horizon / APEX DXA) - AUTHORIZED white-box pentest
 Finding    : F-SAFE-005 / TC-SAFE-005  (Kernel-IOCTL device-object ACL)
 Purpose    : RESOLVE the ComCon kernel driver's device object + interface and
              READ its effective DACL/SDDL. Determines whether a NON-privileged
              user can open a handle to the safety-critical acquisition channel.

 SAFETY     : *** NON-ACTUATING / READ-ONLY ***
              This script ONLY resolves the device path, reads security metadata,
              and (optionally) attempts a bare handle OPEN that mirrors the app
              (DesiredAccess = 0). It sends **NO DeviceIoControl / NO IOCTL**.
              It therefore cannot move the gantry, energize X-ray, or drive the
              DAS/detector. It is safe to run outside the motion-safety envelope.
              Do NOT extend this script to call DeviceIoControl on a real unit
              outside an isolated lab with safety approval.

 Source basis (why this is the right object):
   Driver     : KMDF PnP FDO. Variants: ComConKernel, ComConKernel2,
                ComConKernel_64Bit, ConConKernel2_64Bit, ConConKernel2_64Bit_DMA
   Interface  : WdfDeviceCreateDeviceInterface(GUID_DEVINTERFACE_COMCON)
   GUID       : {978E0AFB-721A-4259-B951-1D2D3AD274B1}  (public.h)
   Security   : NO WdfDeviceInitAssignSDDLString / NO IoCreateDeviceSecure in any
                variant -> interface DACL = INF-supplied SDDL or framework DEFAULT.
   IOCTLs     : all COMCOM_IOCTL(x) = CTL_CODE(FILE_DEVICE_UNKNOWN, x,
                METHOD_BUFFERED, FILE_ANY_ACCESS)  -> access gate is the DACL only.
   User open  : CreateFile(name, 0, FILE_SHARE_READ|FILE_SHARE_WRITE, OPEN_EXISTING)
                (HOLXMAPI.CPP OpenDevice) -> a bare handle is enough to drive IOCTLs.

 Usage      : Run once as a STANDARD (non-admin) user  -> the real exposure test.
              Run again elevated (Admin)               -> baseline / full SDDL.
              Capture full console output + a WinObj screenshot for the report.
================================================================================
#>

[CmdletBinding()]
param(
    [string]$InterfaceGuid = '978E0AFB-721A-4259-B951-1D2D3AD274B1',
    [switch]$TryOpen  # attempt the bare, non-actuating handle open (access=0). Still sends NO IOCTL.
)

$ErrorActionPreference = 'Stop'
function Hr($t){ Write-Host ""; Write-Host ("=" * 78) -ForegroundColor DarkCyan; Write-Host $t -ForegroundColor Cyan; Write-Host ("=" * 78) -ForegroundColor DarkCyan }
function Note($t){ Write-Host "[*] $t" -ForegroundColor Gray }
function Good($t){ Write-Host "[+] $t" -ForegroundColor Green }
function Warn($t){ Write-Host "[!] $t" -ForegroundColor Yellow }
function Bad($t){ Write-Host "[VULN] $t" -ForegroundColor Red }

# Who am I / privilege level -------------------------------------------------
Hr "CONTEXT"
$id  = [Security.Principal.WindowsIdentity]::GetCurrent()
$wp  = New-Object Security.Principal.WindowsPrincipal($id)
$adm = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Note ("User        : {0}" -f $id.Name)
Note ("Elevated    : {0}" -f $adm)
Note ("Interface   : {{{0}}} (GUID_DEVINTERFACE_COMCON)" -f $InterfaceGuid)
if ($adm) { Warn "Running elevated -> shows the FULL descriptor. The MEANINGFUL exposure test is running as a STANDARD user." }
else      { Good "Running as standard user -> this is the real 'can a low-priv user reach the hardware?' test." }

# Risky trustees we care about (low-priv principals that must NOT have access) -
$RiskySids = @{
    'S-1-1-0'      = 'Everyone'
    'S-1-5-11'     = 'Authenticated Users'
    'S-1-5-4'      = 'Interactive'
    'S-1-5-32-545' = 'Users (BUILTIN)'
    'S-1-2-0'      = 'Local'
    'S-1-2-1'      = 'Console Logon'
    'S-1-5-113'    = 'Local account'
}

function Analyze-Sddl([string]$sddl, [string]$label) {
    if ([string]::IsNullOrWhiteSpace($sddl)) { Warn "${label}: no SDDL to analyze"; return }
    Good ("$label SDDL:")
    Write-Host "    $sddl" -ForegroundColor White
    try {
        $rsd = New-Object Security.AccessControl.RawSecurityDescriptor($sddl)
    } catch {
        Warn "Could not parse SDDL into ACEs: $($_.Exception.Message)"; return
    }
    Note "Owner : $($rsd.Owner)"
    Note "DACL ACEs:"
    $hit = $false
    foreach ($ace in $rsd.DiscretionaryAcl) {
        $sid = $ace.SecurityIdentifier.Value
        $friendly = $sid
        try { $friendly = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch {}
        $line = "    {0,-6} {1,-28} mask=0x{2:X8}" -f $ace.AceType, $friendly, $ace.AccessMask
        if ($ace.AceType -match 'Allow' -and $RiskySids.ContainsKey($sid)) {
            Bad ("$line   <== LOW-PRIV TRUSTEE HAS ACCESS ($($RiskySids[$sid]))")
            $hit = $true
        } else {
            Write-Host $line -ForegroundColor DarkGray
        }
    }
    if ($hit) {
        Bad "$label GRANTS a low-privilege trustee access to the ComCon channel."
        Bad "=> Any such user can CreateFile() this device and issue FILE_ANY_ACCESS IOCTLs to safety-critical acquisition hardware. F-SAFE-005 CONFIRMED (pending non-actuating open test below)."
    } else {
        Good "$label restricts access to privileged trustees only (no Everyone/Users/Auth-Users/Interactive Allow ACE seen)."
    }
    # Human-readable expansion
    try { Write-Host ""; ConvertFrom-SddlString -Sddl $sddl | Format-List | Out-String | Write-Host } catch {}
}

# ---------------------------------------------------------------------------
# 1) Registry: DeviceClasses -> interface instances + any explicit Security SDDL
# ---------------------------------------------------------------------------
Hr "1) DEVICE INTERFACE INSTANCES (registry, world-readable, no IOCTL)"
$classKey = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\{$InterfaceGuid}"
$devicePaths = @()
if (Test-Path $classKey) {
    Good "Interface class present: $classKey"
    foreach ($inst in Get-ChildItem $classKey -ErrorAction SilentlyContinue) {
        $leaf = Split-Path $inst.PSChildName -Leaf
        # Registry symbolic-link form "##?#PCI#...#{guid}" -> usable Win32 path "\\?\PCI#...#{guid}"
        $devPath = $leaf -replace '^##\?#','\\?\' -replace '#\{',"#{"
        $devPath = $leaf -replace '^##\?#','\\?\'
        Note "Instance: $($inst.PSChildName)"
        Note "  DevicePath: $devPath"
        $devicePaths += $devPath

        # An explicit per-interface Security SDDL (INF: HKR,,Security) lands here if set.
        $ctrl = Join-Path $inst.PSPath '#\Control'
        $secVal = $null
        foreach ($cand in @($ctrl, ($inst.PSPath))) {
            try {
                $p = Get-ItemProperty -Path $cand -Name 'Security' -ErrorAction Stop
                if ($p.Security) { $secVal = $p.Security; break }
            } catch {}
        }
        if ($secVal) {
            try {
                $sddl = (New-Object Security.AccessControl.RawSecurityDescriptor([byte[]]$secVal,0)).GetSddlForm('All')
                Warn "  Explicit INF-supplied Security SDDL found on this interface:"
                Analyze-Sddl $sddl "  [registry Security]"
            } catch { Warn "  Security value present but could not decode: $($_.Exception.Message)" }
        } else {
            Warn "  No explicit 'Security' value on this interface -> DACL is the FRAMEWORK/CLASS DEFAULT (must read live descriptor below)."
        }
    }
} else {
    Warn "Interface class key not found. Either the ComCon driver/hardware is not present on this box,"
    Warn "or the interface has never been enabled. Confirm you are on the acquisition workstation."
}

# Also surface the PnP device + its 'Security' devnode property, if any
Hr "1b) PnP VIEW"
try {
    $pnp = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
           Where-Object { $_.InstanceId -match 'COMCON' -or $_.FriendlyName -match 'ComCon|Hologic|Gantry|Acquisition' }
    if ($pnp) { $pnp | Format-Table -Auto Status,Class,FriendlyName,InstanceId | Out-String | Write-Host }
    else { Note "No obvious ComCon/Hologic PnP node by name (device may present under a generic name)." }
} catch { Note "Get-PnpDevice unavailable: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# 2) LIVE effective DACL of the device object (CreateFile READ_CONTROL + GetSecurityInfo)
#    READ_CONTROL only. NO IOCTL. If a standard user is denied even READ_CONTROL,
#    that itself is evidence the object is locked down.
# ---------------------------------------------------------------------------
Hr "2) LIVE EFFECTIVE DEVICE-OBJECT DACL (read-only handle, NO IOCTL)"
if (-not $devicePaths) { Warn "No device path resolved from registry; skipping live read. Use WinObj (step 4) instead." }

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.ComponentModel;
namespace PtDev {
public static class N {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr templ);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll")]
    public static extern uint GetSecurityInfo(IntPtr h, int objType, int secInfo,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr sd);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
        IntPtr sd, uint rev, int secInfo, out IntPtr str, out int len);
    [DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr p);

    public const uint READ_CONTROL = 0x00020000;
    public const uint OPEN_EXISTING = 3;
    public const int  SE_FILE_OBJECT = 1;
    public const int  DACL_SECURITY_INFORMATION = 0x4;
    public const int  OWNER_SECURITY_INFORMATION = 0x1;
    public const int  GROUP_SECURITY_INFORMATION = 0x2;

    // Open with READ_CONTROL to read the descriptor. Returns SDDL or throws.
    public static string ReadSddl(string path) {
        IntPtr h = CreateFileW(path, READ_CONTROL, 0x1|0x2, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFile(READ_CONTROL) failed");
        try {
            IntPtr sd;
            uint rc = GetSecurityInfo(h, SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out sd);
            if (rc != 0) throw new Win32Exception((int)rc, "GetSecurityInfo failed");
            IntPtr str; int len;
            if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1,
                    OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
                    out str, out len))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ConvertSD failed");
            string s = Marshal.PtrToStringUni(str);
            LocalFree(str);
            return s;
        } finally { CloseHandle(h); }
    }

    // Bare open mirroring the app: DesiredAccess = 0. NO IOCTL is sent.
    public static string TryBareOpen(string path) {
        IntPtr h = CreateFileW(path, 0, 0x1|0x2, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h == new IntPtr(-1)) return "DENIED (Win32 " + Marshal.GetLastWin32Error() + ")";
        CloseHandle(h);
        return "OPENED";
    }
}
}
'@

foreach ($dp in $devicePaths) {
    Note "Device: $dp"
    try {
        $sddl = [PtDev.N]::ReadSddl($dp)
        Analyze-Sddl $sddl "  [live effective]"
    } catch {
        Warn "  Could not read descriptor as this user: $($_.Exception.Message)"
        Note "  (If READ_CONTROL is denied to a standard user, the object is likely NOT world-accessible - good.)"
    }
}

# ---------------------------------------------------------------------------
# 3) NON-ACTUATING handle-open test (opt-in) - mirrors HOLXMAPI OpenDevice()
# ---------------------------------------------------------------------------
Hr "3) NON-ACTUATING OPEN TEST (opt-in via -TryOpen)  ***STOPS AT OPEN - NO IOCTL***"
if ($TryOpen) {
    if (-not $devicePaths) { Warn "No device path to test." }
    foreach ($dp in $devicePaths) {
        $r = [PtDev.N]::TryBareOpen($dp)
        if ($r -eq 'OPENED') {
            Bad "OPEN SUCCEEDED as $($id.Name) with DesiredAccess=0 : $dp"
            Bad "=> This account can obtain a handle. Because every IOCTL is FILE_ANY_ACCESS, this handle is sufficient to issue register/bus/DAS commands. HARD CONFIRMATION of F-SAFE-005 for this trustee."
            Warn "STOPPING HERE. Do NOT send IOCTLs on a real unit outside an approved safety lab."
        } else {
            Good "Open $r as $($id.Name) : $dp  (this trustee cannot get a handle)"
        }
    }
} else {
    Note "Skipped. Re-run with -TryOpen to perform the bare, non-actuating handle open as the current user."
}

Hr "NEXT (manual, for the report)"
Write-Host @"
 * Run this script as a STANDARD user AND as Admin; capture both console outputs.
 * Visual evidence: run Sysinternals WinObj elevated, navigate the device path, right-click
   the object -> Properties -> Security tab, screenshot the ACL. Also inspect
   \GLOBAL??\ for the ComCon symbolic link and \Device\ for the object.
 * Sysinternals accesschk (read-only) cross-check:
       accesschk.exe -nobanner -v "\\.\GLOBALROOT\Device\<name>"
   or, for the interface:  accesschk.exe -nobanner -c <ComCon service>  (SDDL of the object)
 * VERDICT MATRIX (device-object / interface DACL):
     - Allow ACE for Everyone (S-1-1-0), Authenticated Users (S-1-5-11),
       Interactive (S-1-5-4) or Users (S-1-5-32-545)         => F-SAFE-005 CONFIRMED (High/Critical)
     - Only SYSTEM + Administrators (SDDL_DEVOBJ_SYS_ALL_ADM_ALL)  => not exploitable by low-priv (residual: any admin-only svc)
"@ -ForegroundColor Gray
