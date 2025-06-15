# Phase 3: Scenario 5 - Data Exfiltration & Credential Dumping

## Attack Overview
- **Description**: Simulated an attacker on Arch Linux accessing and copying a sensitive file from a Windows VM’s SMB share, mimicking data exfiltration and dumping credentials
- **MITRE ATT&CK**: 
  - [T1048.003 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1048/003/)
  - [T1020 - Automated Exfiltration](https://attack.mitre.org/techniques/T1020/)
- **Objective**: Detect unauthorized file access and SMB transfers using Sysmon and Wazuh.
- **Date and Time**: June 15, 2025, ~01:40 AM IST

## Simulation Details
- **Environment**: 
  - **Target**: Windows 10 (hostname: `DESKTOP-FF0MPJM`, IP: `192.168.1.101`, Wazuh agent: `SIEM-Target-Windows`).
  - **Attacker**: Arch Linux (IP: `192.168.1.55`).
- **Sysmon Config**: SwiftOnSecurity `sysmonconfig-export.xml`.
- **Simulation**:
  1. On Windows:
     ```powershell
     New-Item -ItemType Directory -Path C:\SensitiveData -Force
     Set-Content -Path C:\SensitiveData\secrets.txt -Value "Confidential: Company Secrets"
     New-SmbShare -Name "SensitiveData" -Path C:\SensitiveData -FullAccess "hacker"
     ```
  2. On Arch Linux:
     ```bash
     smbclient //192.168.1.101/SensitiveData -U hacker%P@ssw0rd123 -c "get secrets.txt /tmp/stolen_secrets.txt"
     cat /tmp/stolen_secrets.txt
     ```
- **Expected Events**:
  - **Sysmon Event ID 3**: Connections from `192.168.1.55` to `192.168.1.101:445`.
  - **Sysmon Event ID 11**: Access to `C:\SensitiveData\secrets.txt`.
  - **Windows Security Event ID 5145**: Share access by `hacker`.
  - **Wazuh**: Alerts with rule ID `100011`.

## Detection in Wazuh
- **Wazuh Rule**: Rule ID `100011` (in `custom_rules.xml`):
  ```xml
  <rule id="100011" level="12">
    <if_sid>61603</if_sid>
    <field name="sysmon.destination_ip">192\.168\.1\.55</field>
    <field name="sysmon.destination_port">445</field>
    <field name="sysmon.image">svchost\.exe|smss\.exe</field>
    <description>Suspicious SMB access for data exfiltration</description>
    <mitre>
      <id>T1048.003</id>
    </mitre>
  </rule>
  ```
- **Search Query**:
  ```kql
  rule.id:100011 AND agent.name:SIEM-Target-Windows AND sysmon.destination_ip:192.168.1.55 AND sysmon.destination_port:445
  ```
- **Findings**:
  - Alerts with `rule.id:100011`, `rule.level:12`.
  - Sysmon logs: SMB connections, file access.
- **Screenshots**:
  - `Screenshots/wazuh_alerts_exfil.png`
  - `Screenshots/sysmon_log_exfil.png`
  - `Screenshots/smbclient_output.png`
- **Logs**:
  - `Logs/sysmon_events_exfil.evtx`
  - `Logs/wazuh_agent_filtered_exfil.log`

## Learnings
- **Blue Teaming**: SMB transfers are common for exfiltration. Sysmon and Wazuh detect unauthorized access.
- **Challenges**: Legitimate SMB traffic may trigger false positives; filter by source IP.
- **Technical Growth**: Learned to simulate exfiltration and analyze file access events.
- **Best Practice**: Monitor sensitive folders, restrict SMB shares.

## Detection Logic Query
```kql
rule.id:100011 AND agent.name:SIEM-Target-Windows AND sysmon.destination_ip:192.168.1.55 AND sysmon.destination_port:445
```
- **Purpose**: Detects SMB access from attacker.
- **Outcome**: High-severity alert.

## References
- [MITRE ATT&CK: Exfiltration](https://attack.mitre.org/techniques/T1048/003/)
- [Wazuh Documentation: Sysmon](https://documentation.wazuh.com/current/user-manual/ruleset/sysmon.html)

## Attachments
- **Logs**: [/home/user/Phase3/Scenario-5-DataExfiltration/Logs/](/DetectAndDefend/phase2/Scenario-6-Data-Exfiltartion/Logs/log-1.json)
[/home/user/Phase3/Scenario-5-DataExfiltration/Logs/](/DetectAndDefend/phase2/Scenario-6-Data-Exfiltartion/Logs/log-2.json)
- **Screenshots**:
  1. [Phase3/Scenario-5-DataExfiltration/Screenshots/attack-command-arch.png](/DetectAndDefend/phase2/Scenario-6-Data-Exfiltartion/Screenshots/wazuh-dashboard-logs.png)
  2. [Phase3/Scenario-5-DataExfiltration/Screenshots/wazuh-dashboard-event-logs.png](/DetectAndDefend/phase2/Scenario-6-Data-Exfiltartion/Screenshots/wazuh-dashboard-logs.png)
  3. [Phase3/Scenario-5-DataExfiltration/Screenshots/event-logs-exfil.png](/DetectAndDefend/phase2/Scenario-6-Data-Exfiltartion/Screenshots/wazuh-log-1.png)
  4. [Phase3/Scenario-5-DataExfiltration/Screenshots/event-logs-exfil.png](/DetectAndDefend/phase2/Scenario-6-Data-Exfiltartion/Screenshots/wazuh-log-2.png)