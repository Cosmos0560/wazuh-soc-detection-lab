#!/usr/bin/env bash
set -e

echo "[*] Writing Sysmon configuration..."
cat << 'EOF' > configs/sysmon/sysmon-modular-config.xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>md5,sha256,imphash</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <RuleGroup name="ProcessCreation_Detection" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="end with">\powershell.exe</Image>
        <Image condition="end with">\pwsh.exe</Image>
        <Image condition="end with">\cmd.exe</Image>
        <CommandLine condition="contains">-EncodedCommand</CommandLine>
        <CommandLine condition="contains">-enc</CommandLine>
        <CommandLine condition="contains">-WindowStyle Hidden</CommandLine>
        <CommandLine condition="contains">-ExecutionPolicy Bypass</CommandLine>
        <CommandLine condition="contains">FromBase64String</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\audiodg.exe</Image>
      </ProcessCreate>
    </RuleGroup>
    <RuleGroup name="ProcessAccess_Detection" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
      </ProcessAccess>
      <ProcessAccess onmatch="exclude">
        <SourceImage condition="is">C:\Program Files\Windows Defender\MsMpEng.exe</SourceImage>
        <SourceImage condition="is">C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\System32\csrss.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\System32\wininit.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\System32\svchost.exe</SourceImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
EOF

echo "[*] Writing Wazuh agent configuration..."
cat << 'EOF' > configs/wazuh-agent/ossec.conf
<ossec_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
    <only-future-events>no</only-future-events>
  </localfile>
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID != 5156 and EventID != 5158]</query>
  </localfile>
</ossec_config>
EOF

echo "[*] Writing Architecture documentation..."
cat << 'EOF' > docs/architecture.md
# Detection Engineering Architecture & Pipeline

## Data Pipeline
1. **Simulation:** Safe adversary emulation triggers Windows API calls.
2. **Sysmon Telemetry:** Driver captures EID 1 (Process Create) & EID 10 (ProcessAccess to lsass.exe).
3. **Agent Ingestion:** Wazuh Agent reads Microsoft-Windows-Sysmon/Operational via EventChannel.
4. **Wazuh Manager:** wazuh-analysisd evaluates logs against custom XML rules (100101, 100102).
5. **SOC Playbooks:** High severity alerts redirect analysts to PB-100101 and PB-100102.
EOF

echo "[*] Writing Incident Response Playbooks..."
cat << 'EOF' > docs/playbooks/PB-100101-PowerShell-Exec.md
# SOC Incident Response Playbook: PB-100101

**Rule ID:** 100101  
**Severity:** Level 12 (High)  
**MITRE ATT&CK:** T1059.001, T1027  
**Target:** Sysmon Event ID 1 (Process Creation)

## 1. Initial Triage Checklist
- Extract computer name and user from the alert.
- Decode Base64 string from commandLine argument.
- Verify parent process hierarchy.

## 2. Containment & Remediation
- Isolate endpoint if untrusted external connections or C2 beacons exist.
- Terminate process via PID and collect command line history.
EOF

cat << 'EOF' > docs/playbooks/PB-100102-LSASS-Access.md
# SOC Incident Response Playbook: PB-100102

**Rule ID:** 100102  
**Severity:** Level 14 (Critical)  
**MITRE ATT&CK:** T1003.001  
**Target:** Sysmon Event ID 10 (ProcessAccess)

## 1. Initial Triage Checklist
- Verify calling process (sourceImage).
- Inspect AccessMask (0x1410, 0x143a, 0x1fffff).
- Inspect call trace for unbacked modules.

## 2. Immediate Containment
- Instantly isolate host from enterprise network to prevent credential theft spread.
- Invalidate Active Directory Kerberos tickets (klist purge) and force password reset.
EOF

echo "[*] Git Staging and Committing..."
git add .
git commit -m "feat: add Sysmon/Wazuh configs, DaC architecture, and SOC playbooks"

echo "[*] Pushing to GitHub..."
git push origin main
echo "[+] Phase 2 deployed and pushed successfully!"