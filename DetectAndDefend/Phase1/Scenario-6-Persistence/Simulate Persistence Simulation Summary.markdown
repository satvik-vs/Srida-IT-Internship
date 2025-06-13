# Simulate Persistence Simulation Summary

## Attack Overview
- **Description**: Simulated persistence by copying `evil.exe` (a renamed notepad.exe) to the Startup folder, ensuring it runs at user login.
- **MITRE ATT&CK**: [T1547.001 - Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- **Objective**: Detect unauthorized file creation in the Startup folder.
- **Date and Time**: June 14, 2025, ~12:50 AM IST

## Simulation Details
- **Environment**: Windows 10 VM (hostname: `DESKTOP-FF0MPJM`, Wazuh agent: `SIEM-Target-Windows`).
- **Sysmon Config**: SwiftOnSecurity `sysmonconfig-export.xml`.
- **Simulation Script**:
  ```powershell
  $testFile = "C:\Users\Public\evil.exe"
  Copy-Item -Path "C:\Windows\System32\notepad.exe" -Destination $testFile
  $startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
  Copy-Item -Path $testFile -Destination "$startupFolder\evil.exe"
  ```
- **Execution**: Ran `simulate_persistence.ps1` as standard user.
- **Expected Events**:
  - **Sysmon Event ID 11**: File creation in `...\Startup\evil.exe`.

## Detection
- **Sysmon Detection**:
  - Expected in Event Viewer (`Microsoft-Windows-Sysmon/Operational`):
    - Event ID 11 for `TargetFilename: ...\Startup\evil.exe`.
- **Wazuh Detection**:
  - Expected Wazuh rule: `61601` (Event ID 11).
  - Search Query (Wazuh Dashboard > Security Events > Discover):
    ```kql
    event.code:11 AND win.eventdata.targetFilename:*Startup\\evil.exe
    ```
  - **Findings**:
    - Alerts for `event.code:11` with `win.eventdata.targetFilename: ...\Startup\evil.exe` (pending Wazuh confirmation).
  - **Troubleshooting** (if no alerts):
    - Verified `ossec.conf` for Sysmon log collection.
    - Checked Wazuh agent connectivity (port 1514).
    - Monitored `ossec.log` for errors.
- **Screenshots**:
  - `screenshots\wazuh_alerts_persistence.png`: Wazuh alerts (or empty if issue persists).
  - `screenshots\event_viewer_sysmon.png`: Sysmon Event ID 11.
  - `screenshots\startup_folder.png`: Startup folder with `evil.exe`.
- **Logs**:
  - `logs\sysmon_events.csv`: Sysmon events.
  - `logs\wazuh_agent_filtered.log`: Wazuh agent logs.

## Learnings
- **Blue Teaming Insight**: Startup folder is an easy persistence target. Sysmon’s file logging detects such changes.
- **Challenges**: Legitimate apps use Startup folder, requiring filename analysis.
- **Technical Growth**: Learned to simulate persistence and query Wazuh for file events.
- **Best Practice**: Monitor Startup folder and use Autoruns for baseline checks.

## Detection Logic Query
```kql
event.code:11 AND win.eventdata.targetFilename:*Startup\\evil.exe AND @timestamp:>=now-10m
```
- **Purpose**: Detects file creation in Startup folder.
- **Outcome**: Flags persistence attempts.

## References
- [MITRE ATT&CK: Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [Wazuh Documentation: Sysmon Integration](https://documentation.wazuh.com/current/user-manual/capabilities/sysmon.html)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)

## Attachments
- **Logs**: 
1. [ Log 1 ](/DetectAndDefend/Phase1/Scenario-6-Persistence/logs/log1.json)
2. [ Log 2 ](/DetectAndDefend/Phase1/Scenario-6-Persistence/logs/log2.json)
- **Screenshots**: 
1. [sysmon event log 1 ](/DetectAndDefend/Phase1/Scenario-6-Persistence/screenshots/sysmon-event-log1.png)
2. [ Sysmon Event log 2 ](/DetectAndDefend/Phase1/Scenario-6-Persistence/screenshots/sysmon-event-log2.png)
3. [ Wazuh Dashboard Events with Detection Logic](/DetectAndDefend/Phase1/Scenario-6-Persistence/screenshots/wazuh-dashboard-events.png)
4. [ Wazuh event log 1](/DetectAndDefend/Phase1/Scenario-6-Persistence/screenshots/wazuh-log-1-event.png)
5. [ Wazuh Event Log 2](/DetectAndDefend/Phase1/Scenario-6-Persistence/screenshots/wazuh-event-log-2.png)