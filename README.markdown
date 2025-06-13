# DetectAndDefend Internship Project

## Overview
The **DetectAndDefend** internship, provided by **Srida IT**, focuses on developing blue teaming skills through hands-on simulations of cyber attacks, log analysis, and detection using Security Information and Event Management (SIEM) tools. The project is structured into three phases, each comprising multiple scenarios that simulate real-world attack techniques aligned with the MITRE ATT&CK framework. The goal is to enhance skills in threat detection, log collection, and incident reporting using tools like Sysmon, Wazuh, and Windows Event Logs.

## Internship Details
- **Name**: DetectAndDefend
- **Organization**: Srida IT
- **Duration**: June 2025 (ongoing)
- **Objective**: Simulate cyber attacks, configure logging, detect threats using Wazuh SIEM, and document findings for a blue teaming portfolio.
- **Key Skills**:
  - Threat detection and log analysis
  - Sysmon configuration (SwiftOnSecurity)
  - Wazuh SIEM setup and querying
  - MITRE ATT&CK mapping
  - PowerShell and Bash scripting
  - Windows and Linux environments

## My Setup
The simulations were conducted in a virtualized lab environment to ensure safety and realism:
- **Windows 10 VM**:
  - Hostname: `DESKTOP-FF0MPJM`
  - Wazuh Agent: `SIEM-Target-Windows`
  - IP: `192.168.1.101` (example)
  - Tools: Sysmon (SwiftOnSecurity config), Wazuh Agent, PowerShell
  - Logs: Windows Event Logs, Sysmon Logs
- **Arch Linux VM** (for attack simulation):
  - IP: `192.168.1.55` (example)
  - Tools: `nmap`, `netcat`
- **Wazuh Elite SIEM**:
  - Manager: Hosted on a separate system (IP: `<wazuh_manager_ip>`, port: 1514)
  - Dashboard: Used for querying and visualizing alerts
- **Virtualization**: VirtualBox/VMware
- **Repository**: `cyber-intern-phase-1` (GitHub)
- **Time Zone**: Indian Standard Time (IST), simulations conducted after-hours (e.g., June 14, 2025, ~1-2 AM IST)

## Directory Structure
The repository follows a consistent structure across all phases, with each phase containing scenarios, and each scenario including logs, screenshots, scripts, and a main summary file. Below is the current structure for **Phase 1**, with placeholders for **Phase 2** and **Phase 3**.

```
DetectAndDefend/
├── Phase1/
│   ├── Scenario-1-BruteForce/
│   │   ├── Brute Force Simulation Summary.markdown
│   │   ├── Logs/
│   │   │   ├── log1.json
│   │   │   ├── log2.json
│   │   │   ├── log3.json
│   │   │   ├── log4.json
│   │   │   ├── log5.json
│   │   │   └── log6.json
│   │   ├── Screenshots/
│   │   │   ├── attack-commmand-arch-link-crackmeexec.png
│   │   │   ├── event-logs-1-dashboard.png
│   │   │   └── wazuh-dashboard-event-logs.png
│   │   └── Scripts/ (optional, not present in this scenario)
│   ├── Scenario-2-Malicious File Activity/
│   │   ├── Malware Detection Simulation Summary.markdown
│   │   ├── pla.txt
│   │   ├── logs/
│   │   │   └── log.json
│   │   ├── screenshots/
│   │   │   ├── event-log-1.png
│   │   │   ├── wazuh-dashboard-with-events-deteced.png
│   │   │   └── windows-powershell-execution.png
│   │   └── Scripts/ (optional, not present in this scenario)
│   ├── scenario-3-Data-Exfiltration/
│   │   ├── Updated Data Exfiltration Detection Simulation Summary.markdown
│   │   ├── logs/
│   │   │   └── log1.json
│   │   ├── screenshots/
│   │   │   ├── arch-linux-nc-listener-with-script.png
│   │   │   ├── sysmon-event-log.png
│   │   │   ├── wazuh-dashboard-events-logged.png
│   │   │   └── windows-script-execution-with-nc.-and-script.png
│   │   └── scripts/
│   │       ├── data_exfiltration.ps1
│   │       └── netcat.sh
│   ├── scenario-4-Suspicious PowerShell Usage/
│   │   ├── Suspicious PowerShell Usage Simulation Summary.markdown
│   │   ├── logs/
│   │   │   └── log1.json
│   │   ├── screenshots/
│   │   │   ├── sysmon-detected-log.png
│   │   │   ├── wazuh-dashboard-with-log-and-detection-logic.png
│   │   │   └── wazuh-log-1.png
│   │   └── scripts/
│   │       └── suspicious_usage.ps1
│   ├── scenario-5-Registry Modification/
│   │   ├── Registry Modification Simulation Summary.markdown
│   │   ├── Logs/
│   │   │   └── log1.json
│   │   ├── Screenshots/
│   │   │   ├── sysmon-log-windows.png
│   │   │   ├── wazuh-dahsboard.png
│   │   │   └── windows-powershell.png
│   │   └── scripts/
│   │       └── registry_mod.ps1
│   ├── Scenario-6-Persistence/
│   │   ├── Simulate Persistence Simulation Summary.markdown
│   │   ├── logs/
│   │   │   ├── log1.json
│   │   │   └── log2.json
│   │   ├── screenshots/
│   │   │   ├── sysmon-event-log1.png
│   │   │   ├── sysmon-event-log2.png
│   │   │   ├── wazuh-dashboard-events.png
│   │   │   ├── wazuh-event-log-2.png
│   │   │   └── wazuh-log-1-event.png
│   │   └── scripts/
│   │       └── persistence.ps1
│   ├── Scenario-7-Privilege Abuse/
│   │   ├── Create Local User Simulation Summary.markdown
│   │   ├── logs/
│   │   │   ├── log1.json
│   │   │   ├── log2.json
│   │   │   ├── log3.json
│   │   │   ├── log4.json
│   │   │   └── log5.json
│   │   ├── screenshots/
│   │   │   ├── sysmon-event-log-1.png
│   │   │   ├── sysmon-event-log-2.png
│   │   │   ├── sysmon-log-event-3.png
│   │   │   ├── sysmon-log-event-4.png
│   │   │   ├── wazuh-dashboard-with-events-1.png
│   │   │   ├── wazuh-dashboard-with-events-2.png
│   │   │   ├── wazuh-event-log01.png
│   │   │   ├── wazuh-event-log-03.png
│   │   │   ├── wazuh-event-log-04.png
│   │   │   └── wazuh-event-log-o2.png
│   │   └── scripts/
│   │       └── privilege_abuse.ps1
│   └── scenario-8-Suspicious Scheduled Task/
│       ├── Suspicious Scheduled Task Simulation Summary.markdown
│       ├── logs/
│       │   ├── log1.json
│       │   └── log2.json
│       ├── Screenshots/
│       │   ├── sysmon-event-log-1.png
│       │   ├── sysmon-event-log-2.png
│       │   ├── sysmon-event-log-3.png
│       │   ├── sysmon-repeat-tasks-logged.png
│       │   ├── wazuh-dashboard-events.png
│       │   ├── wazuh-detailed-log1.png
│       │   └── wazuh-detailed-log2.png
│       └── Scripts/
│           └── scheduled_tasks.ps1
├── Phase2/ (Planned, same structure as Phase1)
│   ├── Scenario-1-NameTBD/
│   │   ├── Summary.markdown
│   │   ├── Logs/
│   │   ├── Screenshots/
│   │   └── Scripts/
│   └── Scenario-2-NameTBD/
│       ├── Summary.markdown
│       ├── Logs/
│       ├── Screenshots/
│       └── Scripts/
├── Phase3/ (Planned, same structure as Phase1)
│   ├── Scenario-1-NameTBD/
│   │   ├── Summary.markdown
│   │   ├── Logs/
│   │   ├── Screenshots/
│   │   └── Scripts/
│   └── Scenario-2-NameTBD/
│       ├── Summary.markdown
│       ├── Logs/
│       ├── Screenshots/
│       └── Scripts/
└── README.md
```


## Phase-wise Tasks
The internship is divided into three phases, each focusing on specific attack scenarios and detection techniques. Below is a summary of tasks completed in **Phase 1** and planned for **Phase 2** and **Phase 3**.

### Phase 1: Basic Logging and Detection
**Objective**: Simulate common attack techniques, configure logging with Sysmon and Wazuh, and detect events using Wazuh queries.

**Scenarios**:
1. **Brute Force**:
   - Simulated RDP brute force attempts using `net use`.
   - Detected via Windows Event ID 4625 (Failed Logon).
   - Wazuh query: `event.code:4625`.
2. **Malicious File Activity**:
   - Simulated malware execution using a `.bat` file.
   - Detected via Sysmon Event ID 1 (ProcessCreate).
   - Wazuh query: `event.code:1`.
3. **Data Exfiltration**:
   - Simulated data transfer using `netcat` from Windows to Arch Linux.
   - Detected via Sysmon Event ID 3 (NetworkConnect).
   - Wazuh query: `event.code:3 AND win.eventdata.destinationIp:192.168.1.55`.
4. **Suspicious PowerShell Usage**:
   - Ran a base64-encoded PowerShell command to start `smoch.exe`.
   - Detected via Sysmon Event ID 1.
   - Wazuh query: `win.eventdata.image:powershell.exe AND win.eventdata.commandLine:smoch.exe`.
5. **Registry Modification**:
   - Added a Run key entry for `malware.exe`.
   - Detected via Sysmon Event ID 13 (RegistryValueSet).
   - Wazuh query: `event.code:13 AND win.eventdata.targetObject:*Run\\evil`.
6. **Persistence**:
   - Placed `evil.exe` in the Startup folder.
   - Detected via Sysmon Event ID 11 (FileCreate).
   - Wazuh query: `event.code:11 AND win.eventdata.targetFilename:*Startup\\evil.exe`.
7. **Privilege Abuse**:
   - Created a local user (`attacker`) and added to Administrators.
   - Detected via Windows Event IDs 4720 (User Creation) and 4732 (Group Change).
   - Wazuh query: `event.code:(4720 OR 4732)`.
8. **Suspicious Scheduled Task**:
   - Created a task to run a PowerShell command downloading from `example.com`.
   - Detected via Windows Event ID 4698 (Task Creation) and Sysmon Event ID 1.
   - Wazuh query: `event.code:4698 OR win.eventdata.image:schtasks.exe`.

**Key Deliverables**:
- Simulation scripts (PowerShell, Bash)
- Logs (Sysmon, Windows, Wazuh agent)
- Screenshots (Wazuh dashboard, Event Viewer, Task Scheduler)
- Summaries mapping to MITRE ATT&CK

### Phase 2: Advanced Threat Detection (Planned)
**Objective**: Simulate advanced attack techniques (e.g., fileless attacks, lateral movement) and enhance detection with custom Wazuh rules.

**Scenarios** (Tentative):
1. Fileless Attack Simulation
2. Suspicious Network Connection
3. Additional scenarios TBD

**Key Deliverables**:
- Custom Wazuh rules
- Enhanced detection logic
- Same directory structure as Phase 1

### Phase 3: Incident Response and Reporting (Planned)
**Objective**: Focus on incident response, forensics, and comprehensive reporting for simulated breaches.

**Scenarios** (Tentative):
1. Incident Response Simulation
2. Forensic Analysis
3. Additional scenarios TBD

**Key Deliverables**:
- Incident response reports
- Forensic analysis logs
- Same directory structure as Phase 1

**Notes**:
- Each scenario contains:
  - A main summary file (`.markdown`) detailing the attack, detection, and learnings.
  - `Logs/` folder with JSON or CSV logs (e.g., Sysmon, Wazuh, Windows).
  - `Screenshots/` folder with evidence (e.g., Wazuh dashboard, Event Viewer).
  - `Scripts/` folder with simulation scripts (PowerShell, Bash), where applicable.
- Some scenarios (e.g., 1, 2) lack a `Scripts/` folder if no custom scripts were used.
- Folder naming inconsistencies (e.g., `Logs` vs. `logs`) are preserved as per your structure.

## Summary
The **DetectAndDefend** internship by **Srida IT** has been an invaluable opportunity to develop blue teaming expertise. In **Phase 1**, I successfully simulated eight attack scenarios, configured Sysmon with the SwiftOnSecurity configuration, and used Wazuh Elite to detect and analyze events. Each scenario was mapped to MITRE ATT&CK, documented with logs, screenshots, and scripts, and committed to this repository. Key challenges included troubleshooting Wazuh alert visibility, which improved my understanding of SIEM configuration and log forwarding.

**Phase 2** and **Phase 3** will build on this foundation, focusing on advanced detection and incident response. This project showcases my ability to simulate threats, analyze logs, and document findings, preparing me for a career in cybersecurity.

## Acknowledgments
- **Srida IT** for providing the internship and resources.
- **SwiftOnSecurity** for the Sysmon configuration.
- **Wazuh** for the open-source SIEM platform.

## Contact
For inquiries or feedback, please reach out via GitHub or contact Srida IT.