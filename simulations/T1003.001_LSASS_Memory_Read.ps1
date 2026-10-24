<#
.SYNOPSIS
    Adversary Simulation: MITRE ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory)
.DESCRIPTION
    Uses benign P/Invoke Win32 API calls (OpenProcess & CloseHandle) to request a
    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ (0x1410) handle to lsass.exe without
    reading or dumping memory. Generates Sysmon Event ID 10 telemetry to validate Wazuh Rule 100102.
.NOTES
    Requires an elevated (Administrator) PowerShell session to obtain a valid handle to lsass.exe.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "[*] MITRE ATT&CK T1003.001 Safe P/Invoke Simulation Starting..." -ForegroundColor Cyan

$Win32Signature = @"
using System;
using System.Runtime.InteropServices;

public static class Kernel32Native {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        int dwProcessId
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

if (-not ("Kernel32Native" -as [type])) {
    Add-Type -TypeDefinition $Win32Signature -Language CSharp
}

[uint32]$DesiredAccess = 0x1410

$LsassProc = Get-Process -Name "lsass" -ErrorAction Stop | Select-Object -First 1
Write-Host "[*] Target Process    : lsass.exe (PID: $($LsassProc.Id))" -ForegroundColor Yellow
Write-Host "[*] Requested Access  : 0x1410 (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)" -ForegroundColor Yellow

$Handle = [Kernel32Native]::OpenProcess($DesiredAccess, $false, $LsassProc.Id)

if ($Handle -ne [IntPtr]::Zero) {
    Write-Host "[+] Successfully acquired read handle (0x$($Handle.ToString('X'))) to lsass.exe." -ForegroundColor Green
    Write-Host "[*] Closing handle immediately without reading memory..." -ForegroundColor Cyan
    [void][Kernel32Native]::CloseHandle($Handle)
    Write-Host "[+] Handle closed cleanly. Sysmon Event ID 10 (ProcessAccess) triggered." -ForegroundColor Green
} else {
    $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Warning "[!] OpenProcess returned NULL (Win32 Error Code: $LastError). Run as Administrator to obtain a granted 0x1410 handle."
}
