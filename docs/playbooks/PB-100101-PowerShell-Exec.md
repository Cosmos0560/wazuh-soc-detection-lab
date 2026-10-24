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
