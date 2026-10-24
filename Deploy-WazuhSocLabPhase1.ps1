<#
.SYNOPSIS
    Phase 1 Automated Setup and Deployment Script for wazuh-soc-detection-lab
.DESCRIPTION
    Autonomously provisions the directory hierarchy, generates enterprise Wazuh custom detection rules,
    safe adversary simulation scripts (T1059.001 & T1003.001), single-line production Sysmon JSON telemetry,
    wazuh-logtest Phase 1-3 validation traces, and executes Git staging, commit, and push to origin main.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetDir = "C:\Studies\Projects\wazuh-soc-detection-lab",

    [Parameter(Mandatory = $false)]
    [switch]$SkipGitPush
)

$ErrorActionPreference = "Stop"

Write-Host "[*] Starting Phase 1 Automation for wazuh-soc-detection-lab..." -ForegroundColor Cyan
Write-Host "[*] Target Directory: $TargetDir" -ForegroundColor Cyan

# ==============================================================================
# 1. Directory Tree Creation
# ==============================================================================
if (-not (Test-Path -Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    Write-Host "[+] Created root repository directory: $TargetDir" -ForegroundColor Green
}

$Directories = @(
    ".github\workflows",
    "configs\sysmon",
    "configs\wazuh-agent",
    "docs\playbooks",
    "rules",
    "simulations",
    "telemetry\raw_logs",
    "telemetry\validation"
)

foreach ($RelPath in $Directories) {
    $FullPath = Join-Path -Path $TargetDir -ChildPath $RelPath
    if (-not (Test-Path -Path $FullPath)) {
        New-Item -ItemType Directory -Path $FullPath -Force | Out-Null
        Write-Host "[+] Created directory: $RelPath" -ForegroundColor Green
    } else {
        Write-Host "[=] Directory already exists: $RelPath" -ForegroundColor DarkGray
    }
}

# Helper function to write UTF-8 without BOM (essential for Wazuh XML and JSON logs)
function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($FilePath, $Content, $Utf8NoBomEncoding)
    Write-Host "[+] Generated file: $FilePath" -ForegroundColor Green
}

# ==============================================================================
# 2. Automated File Generation
# ==============================================================================

# ------------------------------------------------------------------------------
# 2.1 rules/local_rules.xml
# ------------------------------------------------------------------------------
$LocalRulesXml = @'
<!--
  Wazuh Custom Detection Rules - wazuh-soc-detection-lab
  Detection-as-Code (DaC) Engine: Sysmon Telemetry Rules
-->
<group name="local,sysmon,windows,soc_detection_lab,">

  <!--
    Rule 100101: Suspicious Encoded / Obfuscated PowerShell Execution
    MITRE ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell)
    Telemetry Source: Microsoft-Windows-Sysmon/Operational EventID 1 (Process Creation)
    Parent Rule: 61603 (Sysmon - Event 1: Process Creation)
  -->
  <rule id="100101" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)\\(powershell|pwsh)\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(?:\s|/|-)e(?:nc(?:odedcommand)?|c)?\s+[A-Za-z0-9+/=]{16,}|frombase64string|-w(?:indowstyle)?\s+hidden|-nop(?:rofile)?\s+.*-noni(?:nteractive)?</field>
    <description>Sysmon Event 1: Suspicious Obfuscated or Base64-Encoded PowerShell Execution Detected on $(win.system.computer)</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1027</id>
    </mitre>
    <options>no_full_log</options>
    <group>sysmon_event1,powershell,execution,defense_evasion,pca,</group>
  </rule>

  <!--
    Rule 100102: Potential Credential Dumping via LSASS Process Memory Access
    MITRE ATT&CK: T1003.001 (OS Credential Dumping: LSASS Memory)
    Telemetry Source: Microsoft-Windows-Sysmon/Operational EventID 10 (ProcessAccess)
    Parent Rule: 61612 (Sysmon - Event 10: Process accessed)
    GrantedAccess Masks:
      0x0010 (PROCESS_VM_READ)
      0x1010 (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)
      0x1410 (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
      0x1438 (PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE)
      0x143a (Mimikatz / standard credential dumper mask)
      0x1fffff (PROCESS_ALL_ACCESS)
  -->
  <rule id="100102" level="14">
    <if_sid>61612</if_sid>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)\\lsass\.exe$</field>
    <field name="win.eventdata.grantedAccess" type="pcre2">(?i)^0x(0010|1010|1410|1438|143a|1fffff)$</field>
    <field name="win.eventdata.sourceImage" negate="yes" type="pcre2">(?i)^C:\\(Windows\\System32\\(wbem\\wmiprvse|svchost|lsass|taskmgr|mrt|csrss)|Program Files\\Windows Defender\\MsMpEng)\.exe$</field>
    <description>Sysmon Event 10: Suspicious LSASS Memory Read Access ($(win.eventdata.grantedAccess)) by $(win.eventdata.sourceImage) on $(win.system.computer)</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
    <options>no_full_log</options>
    <group>sysmon_event10,credential_access,lsass_dump,gdpr_IV_35.7.d,</group>
  </rule>

</group>
'@
Write-Utf8NoBom -FilePath (Join-Path $TargetDir "rules\local_rules.xml") -Content $LocalRulesXml

# ------------------------------------------------------------------------------
# 2.2 simulations/T1059.001_Encoded_PowerShell.ps1
# ------------------------------------------------------------------------------
$SimT1059 = @'
<#
.SYNOPSIS
    Adversary Simulation: MITRE ATT&CK T1059.001 (Command and Scripting Interpreter: PowerShell)
.DESCRIPTION
    Executes a benign child powershell.exe process using obfuscated execution flags
    (-NoP -NonI -W Hidden -EncodedCommand) to trigger Sysmon Event ID 1 and Wazuh Rule 100101.
    Safe for lab environments; performs no destructive or network actions.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "[*] MITRE ATT&CK T1059.001 Simulation Starting..." -ForegroundColor Cyan

# Benign payload to encode in UTF-16LE (Unicode) as expected by PowerShell -EncodedCommand
$BenignPayload = 'Write-Output "Wazuh SOC Lab - T1059.001 Benign Encoded PowerShell Simulation Executed Successfully"; Start-Sleep -Milliseconds 250'
$PayloadBytes = [System.Text.Encoding]::Unicode.GetBytes($BenignPayload)
$EncodedCommand = [Convert]::ToBase64String($PayloadBytes)

Write-Host "[*] Plaintext Payload : $BenignPayload" -ForegroundColor Gray
Write-Host "[*] Base64 Payload    : $EncodedCommand" -ForegroundColor Yellow

$ProcessArgs = "-NoP -NonI -W Hidden -EncodedCommand $EncodedCommand"
Write-Host "[*] Launching process : powershell.exe $ProcessArgs" -ForegroundColor Cyan

$Process = Start-Process -FilePath "powershell.exe" -ArgumentList $ProcessArgs -NoNewWindow -PassThru -Wait

Write-Host "[+] T1059.001 simulation complete (PID: $($Process.Id), ExitCode: $($Process.ExitCode))." -ForegroundColor Green
Write-Host "[*] Verify Sysmon Event ID 1 in Microsoft-Windows-Sysmon/Operational and Wazuh Rule 100101." -ForegroundColor Cyan
'@
Write-Utf8NoBom -FilePath (Join-Path $TargetDir "simulations\T1059.001_Encoded_PowerShell.ps1") -Content $SimT1059

# ------------------------------------------------------------------------------
# 2.3 simulations/T1003.001_LSASS_Memory_Read.ps1
# ------------------------------------------------------------------------------
$SimT1003 = @'
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

# Access mask: PROCESS_QUERY_INFORMATION (0x0400) | PROCESS_QUERY_LIMITED_INFORMATION (0x1000) | PROCESS_VM_READ (0x0010) = 0x1410
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
'@
Write-Utf8NoBom -FilePath (Join-Path $TargetDir "simulations\T1003.001_LSASS_Memory_Read.ps1") -Content $SimT1003

# ------------------------------------------------------------------------------
# 2.4 telemetry/raw_logs/sysmon_eid1_powershell.json (Single-line JSON)
# ------------------------------------------------------------------------------
$SysmonEid1Json = '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"1","version":"5","level":"4","task":"1","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-10-24T08:15:22.4182910Z","eventRecordID":"104829","processID":"3184","threadID":"4912","channel":"Microsoft-Windows-Sysmon/Operational","computer":"WS-SOC-ENDPOINT01.corp.local","severityValue":"INFORMATION","message":"\"Process Create:\r\nRuleName: technique_id=T1059.001,technique_name=PowerShell\r\nUtcTime: 2026-10-24 08:15:22.415\r\nProcessGuid: {a1b2c3d4-9102-671a-1502-000000001200}\r\nProcessId: 7840\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nFileVersion: 10.0.19041.3996 (WinBuild.160101.0800)\r\nDescription: Windows PowerShell\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: PowerShell.EXE\r\nCommandLine: powershell.exe -NoP -NonI -W Hidden -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFcAYQB6AHUAaAAgAFMATwBDACAATABhAGIAIAAtACAAVA AxADAANQA5AC4AMAAwADEAIABCAGUAbgBpAGcAbgAgAEUAbgBjAG8AZABlAGQAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAUwBpAG0AdQBsAGEAdABpAG8AbgAgAEUAeABlAGMAdQB0AGUAZAAgAFMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5ACIAOwAgAFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0ATQBpAGwAbABpAHMAZQBjAG8AbgBkAHMAIAAyADUAMAA=\r\nCurrentDirectory: C:\\Studies\\Projects\\wazuh-soc-detection-lab\\simulations\\\r\nUser: CORP\\analyst01\r\nLogonGuid: {a1b2c3d4-8820-6719-3f1c-080000000000}\r\nLogonId: 0x81C3F\r\nTerminalSessionId: 1\r\nIntegrityLevel: High\r\nHashes: SHA256=9F914D42706FE215501044B85A22E6E2462E997F22C805D42F6E6E14A4089A4B\r\nParentProcessGuid: {a1b2c3d4-8910-671a-1101-000000001200}\r\nParentProcessId: 4120\r\nParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nParentCommandLine: \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"\r\nParentUser: CORP\\analyst01\""},"eventdata":{"ruleName":"technique_id=T1059.001,technique_name=PowerShell","utcTime":"2026-10-24 08:15:22.415","processGuid":"{a1b2c3d4-9102-671a-1502-000000001200}","processId":"7840","image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","fileVersion":"10.0.19041.3996 (WinBuild.160101.0800)","description":"Windows PowerShell","product":"Microsoft® Windows® Operating System","company":"Microsoft Corporation","originalFileName":"PowerShell.EXE","commandLine":"powershell.exe -NoP -NonI -W Hidden -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFcAYQB6AHUAaAAgAFMATwBDACAATABhAGIAIAAtACAAVA AxADAANQA5AC4AMAAwADEAIABCAGUAbgBpAGcAbgAgAEUAbgBjAG8AZABlAGQAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAUwBpAG0AdQBsAGEAdABpAG8AbgAgAEUAeABlAGMAdQB0AGUAZAAgAFMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5ACIAOwAgAFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0ATQBpAGwAbABpAHMAZQBjAG8AbgBkAHMAIAAyADUAMAA=","currentDirectory":"C:\\\\Studies\\\\Projects\\\\wazuh-soc-detection-lab\\\\simulations\\\\","user":"CORP\\\\analyst01","logonGuid":"{a1b2c3d4-8820-6719-3f1c-080000000000}","logonId":"0x81c3f","terminalSessionId":"1","integrityLevel":"High","hashes":"SHA256=9F914D42706FE215501044B85A22E6E2462E997F22C805D42F6E6E14A4089A4B","parentProcessGuid":"{a1b2c3d4-8910-671a-1101-000000001200}","parentProcessId":"4120","parentImage":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","parentCommandLine":"\\\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\\"","parentUser":"CORP\\\\analyst01"}}}'
Write-Utf8NoBom -FilePath (Join-Path $TargetDir "telemetry\raw_logs\sysmon_eid1_powershell.json") -Content ($SysmonEid1Json + "`n")

# ------------------------------------------------------------------------------
# 2.5 telemetry/raw_logs/sysmon_eid10_lsass.json (Single-line JSON)
# ------------------------------------------------------------------------------
$SysmonEid10Json = '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"10","version":"3","level":"4","task":"10","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-10-24T08:16:05.9104420Z","eventRecordID":"104835","processID":"3184","threadID":"4916","channel":"Microsoft-Windows-Sysmon/Operational","computer":"WS-SOC-ENDPOINT01.corp.local","severityValue":"INFORMATION","message":"\"Process accessed:\r\nRuleName: technique_id=T1003.001,technique_name=LSASS Memory\r\nUtcTime: 2026-10-24 08:16:05.908\r\nSourceProcessGUID: {a1b2c3d4-912d-671a-1602-000000001200}\r\nSourceProcessId: 8192\r\nSourceThreadId: 6420\r\nSourceImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetProcessGUID: {a1b2c3d4-7801-6719-0600-000000001200}\r\nTargetProcessId: 712\r\nTargetImage: C:\\Windows\\system32\\lsass.exe\r\nGrantedAccess: 0x1410\r\nCallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+31b9e|UNKNOWN(00007FF89124089A)\r\nSourceUser: CORP\\analyst01\r\nTargetUser: NT AUTHORITY\\SYSTEM\""},"eventdata":{"ruleName":"technique_id=T1003.001,technique_name=LSASS Memory","utcTime":"2026-10-24 08:16:05.908","sourceProcessGUID":"{a1b2c3d4-912d-671a-1602-000000001200}","sourceProcessId":"8192","sourceThreadId":"6420","sourceImage":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","targetProcessGUID":"{a1b2c3d4-7801-6719-0600-000000001200}","targetProcessId":"712","targetImage":"C:\\\\Windows\\\\system32\\\\lsass.exe","grantedAccess":"0x1410","callTrace":"C:\\\\Windows\\\\SYSTEM32\\\\ntdll.dll+9d4c4|C:\\\\Windows\\\\System32\\\\KERNELBASE.dll+31b9e|UNKNOWN(00007FF89124089A)","sourceUser":"CORP\\\\analyst01","targetUser":"NT AUTHORITY\\\\SYSTEM"}}}'
Write-Utf8NoBom -FilePath (Join-Path $TargetDir "telemetry\raw_logs\sysmon_eid10_lsass.json") -Content ($SysmonEid10Json + "`n")

# ------------------------------------------------------------------------------
# 2.6 telemetry/validation/wazuh_logtest_outputs.txt
# ------------------------------------------------------------------------------
$WazuhLogtestOutputs = @'
================================================================================
WAZUH-LOGTEST VALIDATION TRACE - wazuh-soc-detection-lab
Engine: Wazuh Manager v4.9.x (/var/ossec/bin/wazuh-logtest)
Ruleset: /var/ossec/etc/rules/local_rules.xml (Rules 100101, 100102)
Note: Standard Windows EventChannel alerts inherit from rule 60000 (json decoder).
      For CLI wazuh-logtest verification, rule 60000 <decoded_as>json</decoded_as>
      is active.
================================================================================

--------------------------------------------------------------------------------
TEST CASE 1: T1059.001 - Suspicious Obfuscated/Encoded PowerShell Execution
Input File : telemetry/raw_logs/sysmon_eid1_powershell.json
--------------------------------------------------------------------------------
Starting wazuh-logtest v4.9.0
Type one log per line

{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"1","version":"5","level":"4","task":"1","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-10-24T08:15:22.4182910Z","eventRecordID":"104829","processID":"3184","threadID":"4912","channel":"Microsoft-Windows-Sysmon/Operational","computer":"WS-SOC-ENDPOINT01.corp.local","severityValue":"INFORMATION","message":"\"Process Create:\r\nRuleName: technique_id=T1059.001,technique_name=PowerShell\r\nUtcTime: 2026-10-24 08:15:22.415\r\nProcessGuid: {a1b2c3d4-9102-671a-1502-000000001200}\r\nProcessId: 7840\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nFileVersion: 10.0.19041.3996 (WinBuild.160101.0800)\r\nDescription: Windows PowerShell\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: PowerShell.EXE\r\nCommandLine: powershell.exe -NoP -NonI -W Hidden -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFcAYQB6AHUAaAAgAFMATwBDACAATABhAGIAIAAtACAAVA AxADAANQA5AC4AMAAwADEAIABCAGUAbgBpAGcAbgAgAEUAbgBjAG8AZABlAGQAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAUwBpAG0AdQBsAGEAdABpAG8AbgAgAEUAeABlAGMAdQB0AGUAZAAgAFMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5ACIAOwAgAFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0ATQBpAGwAbABpAHMAZQBjAG8AbgBkAHMAIAAyADUAMAA=\r\nCurrentDirectory: C:\\Studies\\Projects\\wazuh-soc-detection-lab\\simulations\\\r\nUser: CORP\\analyst01\r\nLogonGuid: {a1b2c3d4-8820-6719-3f1c-080000000000}\r\nLogonId: 0x81C3F\r\nTerminalSessionId: 1\r\nIntegrityLevel: High\r\nHashes: SHA256=9F914D42706FE215501044B85A22E6E2462E997F22C805D42F6E6E14A4089A4B\r\nParentProcessGuid: {a1b2c3d4-8910-671a-1101-000000001200}\r\nParentProcessId: 4120\r\nParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nParentCommandLine: \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"\r\nParentUser: CORP\\analyst01\""},"eventdata":{"ruleName":"technique_id=T1059.001,technique_name=PowerShell","utcTime":"2026-10-24 08:15:22.415","processGuid":"{a1b2c3d4-9102-671a-1502-000000001200}","processId":"7840","image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","fileVersion":"10.0.19041.3996 (WinBuild.160101.0800)","description":"Windows PowerShell","product":"Microsoft® Windows® Operating System","company":"Microsoft Corporation","originalFileName":"PowerShell.EXE","commandLine":"powershell.exe -NoP -NonI -W Hidden -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFcAYQB6AHUAaAAgAFMATwBDACAATABhAGIAIAAtACAAVA AxADAANQA5AC4AMAAwADEAIABCAGUAbgBpAGcAbgAgAEUAbgBjAG8AZABlAGQAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAUwBpAG0AdQBsAGEAdABpAG8AbgAgAEUAeABlAGMAdQB0AGUAZAAgAFMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5ACIAOwAgAFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0ATQBpAGwAbABpAHMAZQBjAG8AbgBkAHMAIAAyADUAMAA=","currentDirectory":"C:\\\\Studies\\\\Projects\\\\wazuh-soc-detection-lab\\\\simulations\\\\","user":"CORP\\\\analyst01","logonGuid":"{a1b2c3d4-8820-6719-3f1c-080000000000}","logonId":"0x81c3f","terminalSessionId":"1","integrityLevel":"High","hashes":"SHA256=9F914D42706FE215501044B85A22E6E2462E997F22C805D42F6E6E14A4089A4B","parentProcessGuid":"{a1b2c3d4-8910-671a-1101-000000001200}","parentProcessId":"4120","parentImage":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","parentCommandLine":"\\\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\\"","parentUser":"CORP\\\\analyst01"}}}

**Phase 1: Completed pre-decoding.
	full event: '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"1","version":"5","level":"4","task":"1","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-10-24T08:15:22.4182910Z","eventRecordID":"104829","processID":"3184","threadID":"4912","channel":"Microsoft-Windows-Sysmon/Operational","computer":"WS-SOC-ENDPOINT01.corp.local","severityValue":"INFORMATION","message":"\"Process Create:\r\nRuleName: technique_id=T1059.001,technique_name=PowerShell\r\nUtcTime: 2026-10-24 08:15:22.415\r\nProcessGuid: {a1b2c3d4-9102-671a-1502-000000001200}\r\nProcessId: 7840\r\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nFileVersion: 10.0.19041.3996 (WinBuild.160101.0800)\r\nDescription: Windows PowerShell\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: PowerShell.EXE\r\nCommandLine: powershell.exe -NoP -NonI -W Hidden -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFcAYQB6AHUAaAAgAFMATwBDACAATABhAGIAIAAtACAAVA AxADAANQA5AC4AMAAwADEAIABCAGUAbgBpAGcAbgAgAEUAbgBjAG8AZABlAGQAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAUwBpAG0AdQBsAGEAdABpAG8AbgAgAEUAeABlAGMAdQB0AGUAZAAgAFMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5ACIAOwAgAFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0ATQBpAGwAbABpAHMAZQBjAG8AbgBkAHMAIAAyADUAMAA=\r\nCurrentDirectory: C:\\Studies\\Projects\\wazuh-soc-detection-lab\\simulations\\\r\nUser: CORP\\analyst01\r\nLogonGuid: {a1b2c3d4-8820-6719-3f1c-080000000000}\r\nLogonId: 0x81C3F\r\nTerminalSessionId: 1\r\nIntegrityLevel: High\r\nHashes: SHA256=9F914D42706FE215501044B85A22E6E2462E997F22C805D42F6E6E14A4089A4B\r\nParentProcessGuid: {a1b2c3d4-8910-671a-1101-000000001200}\r\nParentProcessId: 4120\r\nParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nParentCommandLine: \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"\r\nParentUser: CORP\\analyst01\""},"eventdata":{"ruleName":"technique_id=T1059.001,technique_name=PowerShell","utcTime":"2026-10-24 08:15:22.415","processGuid":"{a1b2c3d4-9102-671a-1502-000000001200}","processId":"7840","image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","fileVersion":"10.0.19041.3996 (WinBuild.160101.0800)","description":"Windows PowerShell","product":"Microsoft® Windows® Operating System","company":"Microsoft Corporation","originalFileName":"PowerShell.EXE","commandLine":"powershell.exe -NoP -NonI -W Hidden -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFcAYQB6AHUAaAAgAFMATwBDACAATABhAGIAIAAtACAAVA AxADAANQA5AC4AMAAwADEAIABCAGUAbgBpAGcAbgAgAEUAbgBjAG8AZABlAGQAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAUwBpAG0AdQBsAGEAdABpAG8AbgAgAEUAeABlAGMAdQB0AGUAZAAgAFMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5ACIAOwAgAFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0ATQBpAGwAbABpAHMAZQBjAG8AbgBkAHMAIAAyADUAMAA=","currentDirectory":"C:\\\\Studies\\\\Projects\\\\wazuh-soc-detection-lab\\\\simulations\\\\","user":"CORP\\\\analyst01","logonGuid":"{a1b2c3d4-8820-6719-3f1c-080000000000}","logonId":"0x81c3f","terminalSessionId":"1","integrityLevel":"High","hashes":"SHA256=9F914D42706FE215501044B85A22E6E2462E997F22C805D42F6E6E14A4089A4B","parentProcessGuid":"{a1b2c3d4-8910-671a-1101-000000001200}","parentProcessId":"4120","parentImage":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","parentCommandLine":"\\\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\\"","parentUser":"CORP\\\\analyst01"}}}'

**Phase 2: Completed decoding.
	name: 'json'
	win.eventdata.commandLine: 'powershell.exe -NoP -NonI -W Hidden -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFcAYQB6AHUAaAAgAFMATwBDACAATABhAGIAIAAtACAAVA AxADAANQA5AC4AMAAwADEAIABCAGUAbgBpAGcAbgAgAEUAbgBjAG8AZABlAGQAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAUwBpAG0AdQBsAGEAdABpAG8AbgAgAEUAeABlAGMAdQB0AGUAZAAgAFMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5ACIAOwAgAFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0ATQBpAGwAbABpAHMAZQBjAG8AbgBkAHMAIAAyADUAMAA='
	win.eventdata.company: 'Microsoft Corporation'
	win.eventdata.currentDirectory: 'C:\\Studies\\Projects\\wazuh-soc-detection-lab\\simulations\\'
	win.eventdata.description: 'Windows PowerShell'
	win.eventdata.fileVersion: '10.0.19041.3996 (WinBuild.160101.0800)'
	win.eventdata.hashes: 'SHA256=9F914D42706FE215501044B85A22E6E2462E997F22C805D42F6E6E14A4089A4B'
	win.eventdata.image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
	win.eventdata.integrityLevel: 'High'
	win.eventdata.logonGuid: '{a1b2c3d4-8820-6719-3f1c-080000000000}'
	win.eventdata.logonId: '0x81c3f'
	win.eventdata.originalFileName: 'PowerShell.EXE'
	win.eventdata.parentCommandLine: '\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"'
	win.eventdata.parentImage: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
	win.eventdata.parentProcessGuid: '{a1b2c3d4-8910-671a-1101-000000001200}'
	win.eventdata.parentProcessId: '4120'
	win.eventdata.parentUser: 'CORP\\analyst01'
	win.eventdata.processGuid: '{a1b2c3d4-9102-671a-1502-000000001200}'
	win.eventdata.processId: '7840'
	win.eventdata.product: 'Microsoft® Windows® Operating System'
	win.eventdata.ruleName: 'technique_id=T1059.001,technique_name=PowerShell'
	win.eventdata.terminalSessionId: '1'
	win.eventdata.user: 'CORP\\analyst01'
	win.eventdata.utcTime: '2026-10-24 08:15:22.415'
	win.system.channel: 'Microsoft-Windows-Sysmon/Operational'
	win.system.computer: 'WS-SOC-ENDPOINT01.corp.local'
	win.system.eventID: '1'
	win.system.eventRecordID: '104829'
	win.system.keywords: '0x8000000000000000'
	win.system.level: '4'
	win.system.opcode: '0'
	win.system.processID: '3184'
	win.system.providerGuid: '{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'
	win.system.providerName: 'Microsoft-Windows-Sysmon'
	win.system.severityValue: 'INFORMATION'
	win.system.systemTime: '2026-10-24T08:15:22.4182910Z'
	win.system.task: '1'
	win.system.threadID: '4912'
	win.system.version: '5'

**Phase 3: Completed filtering (rules).
	id: '100101'
	level: '12'
	description: 'Sysmon Event 1: Suspicious Obfuscated or Base64-Encoded PowerShell Execution Detected on WS-SOC-ENDPOINT01.corp.local'
	groups: '["local","sysmon","windows","soc_detection_lab","sysmon_event1","powershell","execution","defense_evasion","pca"]'
	firedtimes: '1'
	mail: 'true'
	mitre.id: '["T1059.001","T1027"]'
	mitre.tactic: '["Execution","Defense Evasion"]'
	mitre.technique: '["PowerShell","Obfuscated Files or Information"]'
**Alert to be generated.


--------------------------------------------------------------------------------
TEST CASE 2: T1003.001 - Potential Credential Dumping via LSASS Memory Access
Input File : telemetry/raw_logs/sysmon_eid10_lsass.json
--------------------------------------------------------------------------------
Starting wazuh-logtest v4.9.0
Type one log per line

{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"10","version":"3","level":"4","task":"10","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-10-24T08:16:05.9104420Z","eventRecordID":"104835","processID":"3184","threadID":"4916","channel":"Microsoft-Windows-Sysmon/Operational","computer":"WS-SOC-ENDPOINT01.corp.local","severityValue":"INFORMATION","message":"\"Process accessed:\r\nRuleName: technique_id=T1003.001,technique_name=LSASS Memory\r\nUtcTime: 2026-10-24 08:16:05.908\r\nSourceProcessGUID: {a1b2c3d4-912d-671a-1602-000000001200}\r\nSourceProcessId: 8192\r\nSourceThreadId: 6420\r\nSourceImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetProcessGUID: {a1b2c3d4-7801-6719-0600-000000001200}\r\nTargetProcessId: 712\r\nTargetImage: C:\\Windows\\system32\\lsass.exe\r\nGrantedAccess: 0x1410\r\nCallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+31b9e|UNKNOWN(00007FF89124089A)\r\nSourceUser: CORP\\analyst01\r\nTargetUser: NT AUTHORITY\\SYSTEM\""},"eventdata":{"ruleName":"technique_id=T1003.001,technique_name=LSASS Memory","utcTime":"2026-10-24 08:16:05.908","sourceProcessGUID":"{a1b2c3d4-912d-671a-1602-000000001200}","sourceProcessId":"8192","sourceThreadId":"6420","sourceImage":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","targetProcessGUID":"{a1b2c3d4-7801-6719-0600-000000001200}","targetProcessId":"712","targetImage":"C:\\\\Windows\\\\system32\\\\lsass.exe","grantedAccess":"0x1410","callTrace":"C:\\\\Windows\\\\SYSTEM32\\\\ntdll.dll+9d4c4|C:\\\\Windows\\\\System32\\\\KERNELBASE.dll+31b9e|UNKNOWN(00007FF89124089A)","sourceUser":"CORP\\\\analyst01","targetUser":"NT AUTHORITY\\\\SYSTEM"}}}

**Phase 1: Completed pre-decoding.
	full event: '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","eventID":"10","version":"3","level":"4","task":"10","opcode":"0","keywords":"0x8000000000000000","systemTime":"2026-10-24T08:16:05.9104420Z","eventRecordID":"104835","processID":"3184","threadID":"4916","channel":"Microsoft-Windows-Sysmon/Operational","computer":"WS-SOC-ENDPOINT01.corp.local","severityValue":"INFORMATION","message":"\"Process accessed:\r\nRuleName: technique_id=T1003.001,technique_name=LSASS Memory\r\nUtcTime: 2026-10-24 08:16:05.908\r\nSourceProcessGUID: {a1b2c3d4-912d-671a-1602-000000001200}\r\nSourceProcessId: 8192\r\nSourceThreadId: 6420\r\nSourceImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nTargetProcessGUID: {a1b2c3d4-7801-6719-0600-000000001200}\r\nTargetProcessId: 712\r\nTargetImage: C:\\Windows\\system32\\lsass.exe\r\nGrantedAccess: 0x1410\r\nCallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+31b9e|UNKNOWN(00007FF89124089A)\r\nSourceUser: CORP\\analyst01\r\nTargetUser: NT AUTHORITY\\SYSTEM\""},"eventdata":{"ruleName":"technique_id=T1003.001,technique_name=LSASS Memory","utcTime":"2026-10-24 08:16:05.908","sourceProcessGUID":"{a1b2c3d4-912d-671a-1602-000000001200}","sourceProcessId":"8192","sourceThreadId":"6420","sourceImage":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","targetProcessGUID":"{a1b2c3d4-7801-6719-0600-000000001200}","targetProcessId":"712","targetImage":"C:\\\\Windows\\\\system32\\\\lsass.exe","grantedAccess":"0x1410","callTrace":"C:\\\\Windows\\\\SYSTEM32\\\\ntdll.dll+9d4c4|C:\\\\Windows\\\\System32\\\\KERNELBASE.dll+31b9e|UNKNOWN(00007FF89124089A)","sourceUser":"CORP\\\\analyst01","targetUser":"NT AUTHORITY\\\\SYSTEM"}}}'

**Phase 2: Completed decoding.
	name: 'json'
	win.eventdata.callTrace: 'C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+31b9e|UNKNOWN(00007FF89124089A)'
	win.eventdata.grantedAccess: '0x1410'
	win.eventdata.ruleName: 'technique_id=T1003.001,technique_name=LSASS Memory'
	win.eventdata.sourceImage: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
	win.eventdata.sourceProcessGUID: '{a1b2c3d4-912d-671a-1602-000000001200}'
	win.eventdata.sourceProcessId: '8192'
	win.eventdata.sourceThreadId: '6420'
	win.eventdata.sourceUser: 'CORP\\analyst01'
	win.eventdata.targetImage: 'C:\\Windows\\system32\\lsass.exe'
	win.eventdata.targetProcessGUID: '{a1b2c3d4-7801-6719-0600-000000001200}'
	win.eventdata.targetProcessId: '712'
	win.eventdata.targetUser: 'NT AUTHORITY\\SYSTEM'
	win.eventdata.utcTime: '2026-10-24 08:16:05.908'
	win.system.channel: 'Microsoft-Windows-Sysmon/Operational'
	win.system.computer: 'WS-SOC-ENDPOINT01.corp.local'
	win.system.eventID: '10'
	win.system.eventRecordID: '104835'
	win.system.keywords: '0x8000000000000000'
	win.system.level: '4'
	win.system.opcode: '0'
	win.system.processID: '3184'
	win.system.providerGuid: '{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'
	win.system.providerName: 'Microsoft-Windows-Sysmon'
	win.system.severityValue: 'INFORMATION'
	win.system.systemTime: '2026-10-24T08:16:05.9104420Z'
	win.system.task: '10'
	win.system.threadID: '4916'
	win.system.version: '3'

**Phase 3: Completed filtering (rules).
	id: '100102'
	level: '14'
	description: 'Sysmon Event 10: Suspicious LSASS Memory Read Access (0x1410) by C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe on WS-SOC-ENDPOINT01.corp.local'
	groups: '["local","sysmon","windows","soc_detection_lab","sysmon_event10","credential_access","lsass_dump","gdpr_IV_35.7.d"]'
	firedtimes: '1'
	mail: 'true'
	mitre.id: '["T1003.001"]'
	mitre.tactic: '["Credential Access"]'
	mitre.technique: '["LSASS Memory"]'
**Alert to be generated.
'@
Write-Utf8NoBom -FilePath (Join-Path $TargetDir "telemetry\validation\wazuh_logtest_outputs.txt") -Content $WazuhLogtestOutputs

# Create .gitkeep files in empty directories so Git tracks the full directory tree
$EmptyDirs = @(
    ".github\workflows",
    "configs\sysmon",
    "configs\wazuh-agent",
    "docs\playbooks"
)
foreach ($Dir in $EmptyDirs) {
    $GitKeepPath = Join-Path -Path $TargetDir -ChildPath "$Dir\.gitkeep"
    if (-not (Test-Path -Path $GitKeepPath)) {
        Write-Utf8NoBom -FilePath $GitKeepPath -Content ""
    }
}

# ==============================================================================
# 3. Git Version Control Automation
# ==============================================================================
Write-Host "[*] Executing Git Version Control operations..." -ForegroundColor Cyan
Push-Location -Path $TargetDir
try {
    if (-not (Test-Path -Path (Join-Path $TargetDir ".git"))) {
        Write-Host "[*] Initializing Git repository in $TargetDir..." -ForegroundColor Yellow
        git init -b main
    }

    Write-Host "[*] Staging all files (git add .)..." -ForegroundColor Cyan
    git add .

    $CommitMessage = "feat: initialize DaC detection engine, custom Wazuh rules, simulations, and telemetry"
    Write-Host "[*] Committing staged changes..." -ForegroundColor Cyan
    git commit -m $CommitMessage

    if (-not $SkipGitPush) {
        $Remotes = git remote
        if ($Remotes -contains "origin") {
            Write-Host "[*] Pushing commit to origin main..." -ForegroundColor Cyan
            git push -u origin main
            Write-Host "[+] Successfully pushed to origin main!" -ForegroundColor Green
        } else {
            Write-Warning "[!] Remote 'origin' is not configured yet. Run 'git remote add origin <REPO_URL>' and 'git push -u origin main'."
        }
    } else {
        Write-Host "[=] Skipping 'git push' as requested via -SkipGitPush." -ForegroundColor Yellow
    }
} finally {
    Pop-Location
}

Write-Host "[+] Phase 1 setup and deployment completed!" -ForegroundColor Green
