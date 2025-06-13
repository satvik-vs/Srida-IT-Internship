# Brute Force Simulation Summary

## Attack Overview
- **Description**: Simulated a brute force attack by attempting 6 failed logins for user `conta` using an incorrect password. Brute force attacks aim to guess credentials through repeated login attempts.
- **MITRE ATT&CK**: [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- **Objective**: Demonstrate detection of unauthorized login attempts using Windows Security logs and Wazuh correlation rules.
- **Date and Time**: June 13, 2025, ~09:16 PM IST

## Simulation Details
- **Environment**: Windows 10 VM (hostname: `DESKTOP-FF0MPJM`, Wazuh agent: `SIEM-Target-Windows`).
- **Sysmon Config**: SwiftOnSecurity `sysmonconfig-export.xml`.
- **Simulation Command From my Arch Linux**:
  ```bash
  crackmapexe -winrm 192.168.1.101 -u conta -p /home/bash0x1/pass.txt
  ```
- **Execution**: Ran the command above.
- **Expected Events**:
  - **Windows Event ID 4625**: Failed login attempts logged in Security log.
  - **Sysmon**: No events (SwiftOnSecurity focuses on process/network events).

## Detection in Wazuh
- **Wazuh Rule**: Default rule `60103` detects Event ID 4625, with correlation for 10+ events in 5 minutes.
- **Search Query** (Wazuh Dashboard > Security Events > Discover):
  ```kql
  data.win.system.eventID:4625 AND data.win.eventdata.targetUserName:"conta" AND data.win.eventdata.ipAddress="192.168.1.55" AND rule.description:"logon Failure - Unknown User or bad password"
  ```
- **Findings**:
  - Observed 12+ alerts with `event.code:4625`.
  - High `rule.firedtimes` indicating brute force pattern.
- **Screenshots**:
  - `Screenshots\wazuh_alerts_bruteforce.png`: Wazuh alert list.
  - `Screenshots\event_viewer_4625.png`: Event Viewer showing Event ID 4625.
- **Logs**:
  - `Logs\security_4625.evtx`: Exported Security log.
  - `Logs\wazuh_agent_filtered.log`: Wazuh agent log entries.

## Learnings
- **Blue Teaming Insight**: Brute force attacks are detectable through high-frequency failed login events. Wazuh’s correlation rules (e.g., `frequency=10`) automate detection of patterns.
- **Challenges**: False positives from user errors (e.g., typos) can occur. Mitigation includes tuning rules for specific users or IPs and implementing account lockout policies.
- **Technical Growth**: Learned to query Wazuh using KQL, export Windows logs, and interpret correlation alerts.
- **Best Practice**: Monitor Security logs and set alerts for repeated 4625 events to catch brute force attempts early.

## Detection Logic Query
```kql
data.win.system.eventID:4625 AND data.win.eventdata.targetUserName:"conta" AND data.win.eventdata.ipAddress="192.168.1.55" AND rule.description:"logon Failure - Unknown User or bad password"
```
- **Purpose**: Identifies brute force by counting 10+ failed logins for `conta` in 5 minutes.
- **Outcome**: Alerts on high-count 4625 events, reducing false positives.

## References
- [MITRE ATT&CK: Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Wazuh Documentation: Windows Event Log](https://documentation.wazuh.com/current/user-manual/ruleset/rules/ruleset-windows.html)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)

## Attachments
- **Logs**: [](/DetectAndDefend/Phase1/Scenario-1-BruteForce/Logs/)
- **Screenshots**: 
1. [Attack Simulaton from Arch Linux ](/DetectAndDefend/Phase1/Scenario-1-BruteForce/Screenshots/attack-commmand-arch-link-crackmeexec.png)
2. [Wazuh Dashobard with Event Logs](/DetectAndDefend/Phase1/Scenario-1-BruteForce/Screenshots/wazuh-dashboard-event-logs.png)
3. [Wazuh Dashobard With Event Logs Only ! ](/DetectAndDefend/Phase1/Scenario-1-BruteForce/Screenshots/event-logs-1-dashboard.png)