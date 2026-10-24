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
