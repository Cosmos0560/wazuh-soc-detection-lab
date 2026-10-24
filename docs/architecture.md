# Detection Engineering Architecture & Pipeline

## Data Pipeline
1. **Simulation:** Safe adversary emulation triggers Windows API calls.
2. **Sysmon Telemetry:** Driver captures EID 1 (Process Create) & EID 10 (ProcessAccess to lsass.exe).
3. **Agent Ingestion:** Wazuh Agent reads Microsoft-Windows-Sysmon/Operational via EventChannel.
4. **Wazuh Manager:** wazuh-analysisd evaluates logs against custom XML rules (100101, 100102).
5. **SOC Playbooks:** High severity alerts redirect analysts to PB-100101 and PB-100102.
