# Suspicious PowerShell Usage Simulation Summary

## Attack Overview
- **Description**: Simulated suspicious PowerShell activity by running a base64-encoded command to start `smoch.exe`, mimicking obfuscated malicious scripting.
- **MITRE ATT&CK**: [T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/), [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- **Objective**: Detect obfuscated PowerShell execution.
- **Date and Time**: June 14, 2025, ~12:15 AM IST

## Simulation Details
- **Environment**: Windows 10 VM (hostname: `DESKTOP-FF0MPJM`, Wazuh agent: `SIEM-Target-Windows`).
- **Sysmon Config**: SwiftOnSecurity `sysmonconfig-export.xml`.
- **Simulation Script**:
  ```powershell
  powershell -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACIAcwBtAG8AYwBoAC4AZQB4AGUAIgA=
  ```
- **Execution**: Ran `suspicious_powershell.ps1` in PowerShell as a standard user.
- **Expected Events**:
  - **Sysmon Event ID 1**: `powershell.exe` with base64 command.

## Detection
- **Sysmon Detection**:
  - Expected in Event Viewer (`Microsoft-Windows-Sysmon/Operational`):
    - Event ID 1 for `Image: powershell.exe`, `CommandLine: -enc ... smoch.exe`.
- **Wazuh Detection**:
  - Expected Wazuh rule: `61613` (Event ID 1).
  - Search Query (Wazuh Dashboard > Security Events > Discover):
    ```kql
    data.win.system.eventID:1 AND data.win.eventdata.image:*powershell.exe*
    ```
  - **Findings**:
    - Alerts for `event.code:1` with `win.eventdata.commandLine` containing `smoch.exe` or `-enc` (pending Wazuh confirmation).
  - **Troubleshooting** (if no alerts):
    - Verified `ossec.conf` for Sysmon log collection.
    - Checked Wazuh agent connectivity (port 1514).
    - Monitored `ossec.log` for errors.
- **Screenshots**:
  - `screenshots\wazuh_alerts_powershell.png`: Wazuh alerts (or empty if issue persists).
  - `screenshots\event_viewer_sysmon.png`: Sysmon Event ID 1.
- **Logs**:
  - `logs\sysmon_events.csv`: Sysmon events.
  - `logs\wazuh_agent_filtered.log`: Wazuh agent logs.

## Learnings
- **Blue Teaming Insight**: Base64-encoded PowerShell commands are a red flag. Sysmon’s process logging captures these effectively.
- **Challenges**: Legitimate scripts using `-enc` require context analysis.
- **Technical Growth**: Learned to detect obfuscated PowerShell and query Wazuh for command line patterns.
- **Best Practice**: Enable PowerShell ScriptBlockLogging and monitor for unusual process names.

## Detection Logic Query
```kql
data.win.system.eventID:1 AND data.win.eventdata.image:*powershell.exe*

```
- **Purpose**: Detects suspicious PowerShell execution.
- **Outcome**: Flags obfuscated commands.

## References
- [MITRE ATT&CK: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Wazuh Documentation: Sysmon Integration](https://documentation.wazuh.com/current/user-manual/capabilities/sysmon.html)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)

## Attachments
- **Logs**: [Wazuh Log in JSON](/DetectAndDefend/Phase1/scenario-4-Suspicious%20PowerShell%20Usage/logs/log1.json)
- **Screenshots**: 
1. [Sysomn Log Detection ](/DetectAndDefend/Phase1/scenario-4-Suspicious%20PowerShell%20Usage/screenshots/sysmon-detected-log.png)
2. [wazuh Dashobard with Event](/DetectAndDefend/Phase1/scenario-4-Suspicious%20PowerShell%20Usage/screenshots/wazuh-dashboard-with-log-and-detection-logic.png)
3. [wazuh Log 1](/DetectAndDefend/Phase1/scenario-4-Suspicious%20PowerShell%20Usage/screenshots/wazuh-log-1.png)
