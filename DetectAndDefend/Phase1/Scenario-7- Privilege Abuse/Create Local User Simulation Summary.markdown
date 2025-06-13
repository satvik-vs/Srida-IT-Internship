# Create Local User Simulation Summary

## Attack Overview
- **Description**: Simulated privilege abuse by creating a local user (`attacker`) and adding it to the Administrators group, mimicking a backdoor account.
- **MITRE ATT&CK**: [T1136.001 - Local Account](https://attack.mitre.org/techniques/T1136/001/), [T1078.003 - Local Accounts](https://attack.mitre.org/techniques/T1078/003/)
- **Objective**: Detect unauthorized user creation and privilege escalation.
- **Date and Time**: June 14, 2025, ~1:10 AM IST

## Simulation Details
- **Environment**: Windows 10 VM (hostname: `DESKTOP-FF0MPJM`, Wazuh agent: `SIEM-Target-Windows`).
- **Sysmon Config**: SwiftOnSecurity `sysmonconfig-export.xml`.
- **Simulation Script**:
  ```powershell
  net user attacker P@ssword123 /add
  net localgroup administrators attacker /add
  ```
- **Execution**: Ran `create_local_user.ps1` as Administrator.
- **Expected Events**:
  - **Windows Event ID 4720**: User `attacker` creation.
  - **Windows Event ID 4732**: `attacker` added to Administrators.
  - **Sysmon Event ID 1**: `net.exe` execution.

## Detection
- **Windows Detection**:
  - Expected in Event Viewer (`Windows Logs > Security`):
    - Event ID 4720 for `Account Name: attacker`.
    - Event ID 4732 for `Group Name: Administrators`.
  - Expected in `Microsoft-Windows-Sysmon/Operational`:
    - Event ID 1 for `Image: net.exe`.
- **Wazuh Detection**:
  - Expected Wazuh rules: `60004` (Event ID 4720), `60007` (Event ID 4732), `61613` (Event ID 1).
  - Search Query (Wazuh Dashboard > Security Events > Discover):
    ```kql
    data.win.system.eventID: (4720 OR 4738 OR 4722 OR 4732)
AND agent.name: "SIEM-Target-Windows"
AND agent.ip: "192.168.1.101"
AND data.win.system.channel: "Security"
e
    ```
  - **Findings**:
    - Alerts for `event.code:4720`, `event.code:4732`, or `win.eventdata.image:net.exe` (pending Wazuh confirmation).
  - **Troubleshooting** (if no alerts):
    - Verified `ossec.conf` for Security and Sysmon log collection.
    - Ensured auditing for “User Account Management” and “Security Group Management”.
    - Checked Wazuh agent connectivity (port 1514).
    - Monitored `ossec.log` for errors.
- **Screenshots**:
  - `screenshots\wazuh_alerts_user.png`: Wazuh alerts (or empty if issue persists).
  - `screenshots\event_viewer_security.png`: Security Event ID 4720/4732.
  - `screenshots\user_management.png`: `attacker` in Users/Administrators.
- **Logs**:
  - `logs\security_events.csv`: Security events.
  - `logs\sysmon_events.csv`: Sysmon events.
  - `logs\wazuh_agent_filtered.log`: Wazuh agent logs.

## Learnings
- **Blue Teaming Insight**: Unauthorized user accounts are a persistence/escalation risk. Security logs and Sysmon detect these changes.
- **Challenges**: Legitimate user management requires account baselining.
- **Technical Growth**: Learned to simulate privilege abuse and query Wazuh for account events.
- **Best Practice**: Monitor account creation and restrict administrative group changes.

## Detection Logic Query
```kql
data.win.system.eventID: (4720 OR 4738 OR 4722 OR 4732)
AND agent.name: "SIEM-Target-Windows"
AND agent.ip: "192.168.1.101"
AND data.win.system.channel: "Security"

```
- **Purpose**: Detects user creation and group changes for `attacker`.
- **Outcome**: Flags privilege abuse.

## References
- [MITRE ATT&CK: Local Account](https://attack.mitre.org/techniques/T1136/001/)
- [Wazuh Documentation: Sysmon Integration](https://documentation.wazuh.com/current/user-manual/capabilities/sysmon.html)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)

## Attachments
- **Logs**: 
1. [ Log 1 ](/DetectAndDefend/Phase1/Scenario-7-%20Privilege%20Abuse/logs/log1.json)
2. [ Log 2 ](/DetectAndDefend/Phase1/Scenario-7-%20Privilege%20Abuse/logs/log2.json)
3. [ Log 3 ](/DetectAndDefend/Phase1/Scenario-7-%20Privilege%20Abuse/logs/log3.json)
4. [ Log 4 ](/DetectAndDefend/Phase1/Scenario-7-%20Privilege%20Abuse/logs/log4.json)
5. [ Log 5 ](/DetectAndDefend/Phase1/Scenario-7-%20Privilege%20Abuse/logs/log5.json)
- **Screenshots**: 
1. [ Sysmon Log 1 - Windows](/DetectAndDefend/Phase1/Scenario-7-%20Privilege%20Abuse/screenshots/sysmon-event-log-1.png)
2. [ Sysmon Log 2 - Windows](/DetectAndDefend/Phase1/Scenario-7-%20Privilege%20Abuse/screenshots/sysmon-event-log-2.png)
3. [ Sysmon Log 3 - Windows](/DetectAndDefend/Phase1/Scenario-7-%20Privilege%20Abuse/screenshots/sysmon-log-event-3.png)
4. [ Sysmon Log 4 - Windows](/DetectAndDefend/Phase1/Scenario-7-%20Privilege%20Abuse/screenshots/sysmon-log-event-4.png)
5. [ Wazuh Dashboard with Logs ](/DetectAndDefend/Phase1/Scenario-7-%20Privilege%20Abuse/screenshots/wazuh-dashboard-with-events-1.png)
6. [ Wazuh Dashboard with Logs ](/DetectAndDefend/Phase1/Scenario-7-%20Privilege%20Abuse/screenshots/wazuh-dashboard-with-events-2.png)
7. [Wazuh Event Log 1 Detailed](/DetectAndDefend/Phase1/Scenario-7-%20Privilege%20Abuse/screenshots/wazuh-event-log01.png)
8. [Wazuh Event Log 2 Detailed](/DetectAndDefend/Phase1/Scenario-7-%20Privilege%20Abuse/screenshots/wazuh-event-log-o2.png)
9. [Wazuh Event Log 3 Detailed](/DetectAndDefend/Phase1/Scenario-7-%20Privilege%20Abuse/screenshots/wazuh-event-log-03.png)
10. [Wazuh Event Log 4 Detailed](/DetectAndDefend/Phase1/Scenario-7-%20Privilege%20Abuse/screenshots/wazuh-event-log-04.png)