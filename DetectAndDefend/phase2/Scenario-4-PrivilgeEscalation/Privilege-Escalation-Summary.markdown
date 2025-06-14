# Phase 2: Scenario 4 - Privilege Escalation

## Attack Overview
- **Description**: Simulated an attacker executing commands on the Windows VM to create a new local user and add it to the Administrators group, mimicking a privilege escalation attempt to gain persistent admin access.
- **MITRE ATT&CK**: 
  - [T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002/)
  - [T1136.001 - Persistence: Create Account](https://attack.mitre.org/techniques/T1136/001/)
- **Objective**: Demonstrate detection of user creation and group modification using Sysmon and Wazuh on Windows.
- **Date and Time**: June 15, 2025, ~12:28 AM IST

## Simulation Details
- **Environment**: 
  - **Target**: Windows 10 (hostname: `DESKTOP-FF0MPJM`, IP: `192.168.1.36`, Wazuh agent: `SIEM-Target-Windows`).
  - **Attacker**: Commands executed locally.
- **Sysmon Config**: SwiftOnSecurity `sysmonconfig-export.xml`.
- **Simulation Command From Windows**:
  In PowerShell:
  ```powershell
  net user hacker P@ssw0rd123 /add
  net localgroup Administrators hacker /add
  ```
- **Execution**:
  1. Created user `hacker` with password `P@ssw0rd123`.
  2. Added `hacker` to Administrators group.
  3. Verified: `net user hacker`, `net localgroup Administrators`.
  4. Cleaned up: `net user hacker /delete` (optional).
- **Expected Events**:
  - **Sysmon Event ID 1**: `net.exe` for user creation and group modification.
  - **Windows Security Event ID 4720**: User account created.
  - **Windows Security Event ID 4732**: User added to Administrators.
  - **Wazuh**: Alerts triggered by rule ID 100005.

## Detection in Wazuh
- **Wazuh Rule**: Rule ID 100005 (from `custom_rules.xml`):
  ```xml
  <rule id="100005" level="14">
    <if_sid>61601</if_sid>
    <field name="sysmon.image">net\.exe|net1\.exe</field>
    <field name="sysmon.command_line">user\s+.*\s+/add|localgroup\s+administrators</field>
    <description>Privilege escalation attempt via user creation or group modification</description>
    <mitre>
      <id>T1548.002</id>
    </mitre>
  </rule>
  ```
- **Search Query** (Wazuh Dashboard > Security Events > Discover):
  ```kql
  rule.id:100005 AND agent.name:SIEM-Target-Windows AND sysmon.image:"net.exe" AND sysmon.command_line:("user * /add" OR "localgroup administrators")
  ```
- **Findings**:
  - Observed 1+ alerts with `rule.id:100005`.
  - Sysmon Event ID 1 logged `net.exe` executions.
  - Windows Security Event IDs 4720, 4732 logged user creation and group changes.
  - `rule.level:14` indicates critical alert.
- **Screenshots**:
  - `Screenshots/wazuh_alerts_privilege.png`: Wazuh Dashboard alert list.
  - `Screenshots/sysmon_log_privilege.png`: Sysmon events in Event Viewer.
  - `Screenshots/powershell_privilege_output.png`: PowerShell output.
- **Logs**:
  - `Logs/sysmon_events_privilege.evtx`: Exported Sysmon logs.
  - `Logs/wazuh_agent_filtered_privilege.log`: Wazuh agent logs.

## Learnings
- **Blue Teaming Insight**: User creation and group modifications are critical indicators. Sysmon and Wazuh detect unauthorized `net.exe` usage.
- **Challenges**: Legitimate admin actions may trigger false positives; context helps differentiate.
- **Technical Growth**: Learned to simulate privilege escalation and query Wazuh for command-line patterns.
- **Best Practice**: Enable security auditing and monitor `net.exe` for suspicious arguments.

## Detection Logic Query
```kql
rule.id:100005 AND agent.name:SIEM-Target-Windows AND sysmon.image:"net.exe" AND sysmon.command_line:("user * /add" OR "localgroup administrators")
```
- **Purpose**: Identifies `net.exe` commands for user creation or group modification.
- **Outcome**: Critical alert for privilege escalation.

## References
- [MITRE ATT&CK: Abuse Elevation Control](https://attack.mitre.org/techniques/T1548/002/)
- [MITRE ATT&CK: Create Account](https://attack.mitre.org/techniques/T1136/001/)
- [Wazuh Documentation: Sysmon Integration](https://documentation.wazuh.com/current/user-manual/ruleset/sysmon.html)

## Attachments
- **Logs**: [/home/user/Phase2/Scenario-4-PrivilegeEscalation/Logs/](/DetectAndDefend/phase2/Scenario-4-PrivilgeEscalation/Logs/)
- **Screenshots**:
  1. [Attack Simulation in PowerShell](/DetectAndDefend/phase2/Scenario-4-PrivilgeEscalation/Screenshots/powershell.png)
  2. [Wazuh Dashboard with Event Logs](/DetectAndDefend/phase2/Scenario-4-PrivilgeEscalation/Screenshots/wazuh-db-logs.png)
  3. [Wazuh Dashboard with Event Logs Only! 1 ](/DetectAndDefend/phase2/Scenario-4-PrivilgeEscalation/Screenshots/log1.png)
  4. [Wazuh Dashboard with Event Logs Only! 2](/DetectAndDefend/phase2/Scenario-4-PrivilgeEscalation/Screenshots/log2.png)
  5. [Wazuh Dashboard with Event Logs Only! 3](/DetectAndDefend/phase2/Scenario-4-PrivilgeEscalation/Screenshots/log3.png)