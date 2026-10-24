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
