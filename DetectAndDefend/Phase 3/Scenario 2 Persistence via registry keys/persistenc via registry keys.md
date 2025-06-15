# Scenario 3: Persistence via Registry Run Keys

## Overview
- **Date**: June 15, 2025
- **Target**: Windows 10 VM (IP: 192.168.1.101, Hostname: DESKTOP-FF0MPJM)
- **Attacker**: Arch Linux (IP: 192.168.1.55)
- **User**: testuser (Password: P@ssw0rd123)
- **Attack**: Added a malicious registry run key to execute a batch script at system startup, simulating attacker persistence.
- **Objective**: Demonstrate persistence mechanism, detect via Sysmon and Wazuh, and document for Phase 3 submission.

## Attack Details
- **Method**: A batch script (`malicious.bat`) was delivered via SMB (port 445) to the Windows 10 VM and configured to run at startup by adding an entry to `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`.
- **Execution**:
  - Script copied to `C:\Temp\malicious.bat` via SMB using `smbclient`.
  - Registry key set: `Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Malicious" -Value "C:\Temp\malicious.bat"`.
  - Script content:
    ```batch
    echo Malicious payload executed >> C:\Temp\log.txt
    ```
- **Verification**: Registry key confirmed, script execution tested manually.

## Detection
- **Sysmon**:
  - Event ID 13 (Registry Value Set): Captured modification to Run key.
  - Logs exported: `sysmon_events_persistence.evtx`.
- **Wazuh**:
  - Custom Rule ID: `100017`
    ```xml
    <rule id="100017" level="10">
      <if_sid>61603</if_sid>
      <field name="sysmon.event_id">13</field>
      <field name="sysmon.target_object">Run</field>
      <description>Registry Run Key Persistence</description>
      <mitre><id>T1547.001</id></mitre>
    </rule>
    ```
  - Alert Query: `rule.id:100017 AND agent.name:SIEM-Target-Windows-Local`
  - Screenshot: `wazuh_alert_persistence.png`
- **Wazuh Agent**: Confirmed connected to Wazuh Cloud endpoint.

## MITRE ATT&CK Mapping
- **T1547.001**: Boot or Logon Autostart Execution: Registry Run Keys
  - Added malicious entry to ensure script execution at startup.

## Artifacts
- **Logs**: [ logs ](/DetectAndDefend/Phase%203/Scenario%202%20Persistence%20via%20registry%20keys/Logs/log1.json)
   
- **Screenshots**:
1. [Wazuh Dashbords , Registry Keys , Shell Access , Powershell ](/DetectAndDefend/Phase%203/Scenario%202%20Persistence%20via%20registry%20keys/Screenshots/)
- **Scripts**:
  - `malicious.bat`: Batch script for persistence.
- **Directory**: `/home/user/DetectAndDefend/Phase3/Scenario-3-Persistence/{Logs,Screenshots,Scripts}`

## Challenges
- **Permissions**: Required admin privileges for registry modification; used `Satvik Vemulapalli` if `testuser` lacked access.
- **Metasploit Issues**: Not applicable, as attack used manual scripting.
- **Port 80 Closed**: Relied on SMB (port 445) for delivery.

