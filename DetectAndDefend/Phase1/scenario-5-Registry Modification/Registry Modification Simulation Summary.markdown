# Registry Modification Simulation Summary

## Attack Overview
- **Description**: Simulated a malicious registry modification by adding a Run key entry (`evil`) pointing to `C:\temp\malware.exe`, mimicking persistence.
- **MITRE ATT&CK**: [T1547.001 - Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- **Objective**: Detect unauthorized registry changes for persistence.
- **Date and Time**: June 14, 2025, ~12:35 AM IST

## Simulation Details
- **Environment**: Windows 10 VM (hostname: `DESKTOP-FF0MPJM`, Wazuh agent: `SIEM-Target-Windows`).
- **Sysmon Config**: SwiftOnSecurity `sysmonconfig-export.xml`.
- **Simulation Script**:
  ```powershell
  New-Item -Path "C:\temp" -ItemType Directory -Force
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "evil" -Value "C:\temp\malware.exe"
  ```
- **Execution**: Ran `registry_modification.ps1` as standard user.
- **Expected Events**:
  - **Sysmon Event ID 13**: Registry value set for `HKCU:\...\Run\evil`.

## Detection
- **Sysmon Detection**:
  - Expected in Event Viewer (`Microsoft-Windows-Sysmon/Operational`):
    - Event ID 13 for `TargetObject: ...\Run\evil`, `Details: C:\temp\malware.exe`.
- **Wazuh Detection**:
  - Expected Wazuh rule: `61607` (Event ID 13).
  - Search Query (Wazuh Dashboard > Security Events > Discover):
    ```kql
    event.code:13 AND win.eventdata.targetObject:*Run\\evil
    ```
  - **Findings**:
    - Alerts for `event.code:13` with `win.eventdata.details: C:\temp\malware.exe` (pending Wazuh confirmation).
  - **Troubleshooting** (if no alerts):
    - Verified `ossec.conf` for Sysmon log collection.
    - Checked Wazuh agent connectivity (port 1514).
    - Monitored `ossec.log` for errors.
- **Screenshots**:
  - `screenshots\wazuh_alerts_registry.png`: Wazuh alerts (or empty if issue persists).
  - `screenshots\event_viewer_sysmon.png`: Sysmon Event ID 13.
  - `screenshots\registry_evil.png`: Registry Editor showing `evil` entry.
- **Logs**:
  - `logs\sysmon_events.csv`: Sysmon events.
  - `logs\wazuh_agent_filtered.log`: Wazuh agent logs.

## Learnings
- **Blue Teaming Insight**: Registry Run keys are a key persistence vector. Sysmon’s registry monitoring is critical for detection.
- **Challenges**: Legitimate software modifies Run keys, requiring path analysis.
- **Technical Growth**: Learned to simulate registry attacks and query Wazuh for registry events.
- **Best Practice**: Monitor Run keys and use tools like Autoruns for baseline checks.

## Detection Logic Query
```kql
event.code:13 AND win.eventdata.targetObject:*Run\\evil AND @timestamp:>=now-10m
```
- **Purpose**: Detects registry modifications for persistence.
- **Outcome**: Flags suspicious Run key changes.

## References
- [MITRE ATT&CK: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [Wazuh Documentation: Sysmon Integration](https://documentation.wazuh.com/current/user-manual/capabilities/sysmon.html)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)

## Attachments
- **Logs**: [Log WAZUH](/DetectAndDefend/Phase1/scenario-5-Registry%20Modification/Logs/log1.json)
- **Screenshots**: 
1. [ Sysmon - Log - Windows ](/DetectAndDefend/Phase1/scenario-5-Registry%20Modification/Screenshots/sysmon-log-windows.png)
2. [Windows - Powershell ](/DetectAndDefend/Phase1/scenario-5-Registry%20Modification/Screenshots/windows-powershell.png)
3. [ Wazuh - Dahsboard with Event](/DetectAndDefend/Phase1/scenario-5-Registry%20Modification/Screenshots/wazuh-dahsboard.png)

