# DetectAndDefend Internship Project

## Overview
The **DetectAndDefend** internship, provided by **Srida IT**, focuses on developing blue teaming skills through hands-on simulations of cyber attacks, log analysis, and detection using Security Information and Event Management (SIEM) tools. The project is structured into three phases, each comprising multiple scenarios that simulate real-world attack techniques aligned with the MITRE ATT&CK framework. The goal is to enhance skills in threat detection, log collection, and incident reporting using tools like Sysmon, Wazuh, and Windows Event Logs.

## Internship Details
- **Name**: DetectAndDefend
- **Organization**: Srida IT
- **Duration**: June 2025 (ongoing)
- **Objective**: Simulate cyber attacks, configure logging with Sysmon and Wazuh, detect threats using Wazuh SIEM, and document findings for a blue teaming portfolio.
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
  - IP: `192.168.1.101`
  - Tools: Sysmon (SwiftOnSecurity config), Wazuh Agent, PowerShell
  - Logs: Windows Event Logs, Sysmon Logs
- **Arch Linux VM** (for attack simulation):
  - IP: `192.168.1.55`
  - Tools: `nmap`, `netcat`, `smbclient`, `PsExec` (via Wine)
- **Ubuntu VM** (for attack simulation or Wazuh management):
  - IP: `192.168.1.2`
  - Tools: `nmap`, `smbclient`, Wazuh Manager (potential)
- **Wazuh Elite SIEM**:
  - Manager: Hosted on a separate system (IP: `<wazuh_manager_ip>`, port: 1514, possibly `192.168.1.2`)
  - Dashboard: Used for querying and visualizing alerts
- **Virtualization**: VirtualBox/VMware
- **Repository**: `cyber-intern-phase-1` (GitHub)
- **Time Zone**: Indian Standard Time (IST), simulations conducted after-hours (e.g., June 14–15, 2025, ~1-2 AM IST)

## Directory Structure
The repository follows a consistent structure across all phases, with each phase containing scenarios, and each scenario including logs, screenshots, scripts, and a main summary file. Below is the structure formatted like the output of the `tree` command.

DetectAndDefend/├── Phase1/│   ├── Scenario-1-BruteForce/│   │   ├── Brute Force Simulation Summary.markdown│   │   ├── Logs/│   │   │   ├── log1.json│   │   │   ├── log2.json│   │   │   ├── log3.json│   │   │   ├── log4.json│   │   │   ├── log5.json│   │   │   └── log6.json│   │   └── Screenshots/│   │       ├── attack-commmand-arch-link-crackmeexec.png│   │       ├── event-logs-1-dashboard.png│   │       └── wazuh-dashboard-event-logs.png│   ├── Scenario-2-MaliciousFileActivity/│   │   ├── Malware Detection Simulation Summary.markdown│   │   ├── pla.txt│   │   ├── logs/│   │   │   └── log.json│   │   └── screenshots/│   │       ├── event-log-1.png│   │       ├── wazuh-dashboard-with-events-deteced.png│   │       └── windows-powershell-execution.png│   ├── scenario-3-Data-Exfiltration/│   │   ├── Updated Data Exfiltration Detection Simulation Summary.markdown│   │   ├── logs/│   │   │   └── log1.json│   │   ├── screenshots/│   │   │   ├── arch-linux-nc-listener-with-script.png│   │   │   ├── sysmon-event-log.png│   │   │   ├── wazuh-dashboard-events-logged.png│   │   │   └── windows-script-execution-with-nc.-and-script.png│   │   └── scripts/│   │       ├── data_exfiltration.ps1│   │       └── netcat.sh│   ├── scenario-4-SuspiciousPowerShellUsage/│   │   ├── Suspicious PowerShell Usage Simulation Summary.markdown│   │   ├── logs/│   │   │   └── log1.json│   │   ├── screenshots/│   │   │   ├── sysmon-detected-log.png│   │   │   ├── wazuh-dashboard-with-log-and-detection-logic.png│   │   │   └── wazuh-log-1.png│   │   └── scripts/│   │       └── suspicious_usage.ps1│   ├── scenario-5-RegistryModification/│   │   ├── Registry Modification Simulation Summary.markdown│   │   ├── Logs/│   │   │   └── log1.json│   │   ├── Screenshots/│   │   │   ├── sysmon-log-windows.png│   │   │   ├── wazuh-dahsboard.png│   │   │   └── windows-powershell.png│   │   └── scripts/│   │       └── registry_mod.ps1│   ├── Scenario-6-Persistence/│   │   ├── Simulate Persistence Simulation Summary.markdown│   │   ├── logs/│   │   │   ├── log1.json│   │   │   └── log2.json│   │   ├── screenshots/│   │   │   ├── sysmon-event-log1.png│   │   │   ├── sysmon-event-log2.png│   │   │   ├── wazuh-dashboard-events.png│   │   │   ├── wazuh-event-log-2.png│   │   │   └── wazuh-log-1-event.png│   │   └── scripts/│   │       └── persistence.ps1│   ├── Scenario-7-PrivilegeAbuse/│   │   ├── Create Local User Simulation Summary.markdown│   │   ├── logs/│   │   │   ├── log1.json│   │   │   ├── log2.json│   │   │   ├── log3.json│   │   │   ├── log4.json│   │   │   └── log5.json│   │   ├── screenshots/│   │   │   ├── sysmon-event-log-1.png│   │   │   ├── sysmon-event-log-2.png│   │   │   ├── sysmon-log-event-3.png│   │   │   ├── sysmon-log-event-4.png│   │   │   ├── wazuh-dashboard-with-events-1.png│   │   │   ├── wazuh-dashboard-with-events-2.png│   │   │   ├── wazuh-event-log01.png│   │   │   ├── wazuh-event-log-03.png│   │   │   ├── wazuh-event-log-04.png│   │   │   └── wazuh-event-log-o2.png│   │   └── scripts/│   │       └── privilege_abuse.ps1│   └── scenario-8-SuspiciousScheduledTask/│       ├── Suspicious Scheduled Task Simulation Summary.markdown│       ├── logs/│       │   ├── log1.json│       │   └── log2.json│       ├── Screenshots/│       │   ├── sysmon-event-log-1.png│       │   ├── sysmon-event-log-2.png│       │   ├── sysmon-event-log-3.png│       │   ├── sysmon-repeat-tasks-logged.png│       │   ├── wazuh-dashboard-events.png│       │   ├── wazuh-detailed-log1.png│       │   └── wazuh-detailed-log2.png│       └── Scripts/│           └── scheduled_tasks.ps1├── Phase2/│   ├── Scenario-1-Beaconing/│   │   ├── Summary.markdown│   │   ├── Logs/│   │   ├── Screenshots/│   │   └── Scripts/│   ├── Scenario-2-SuspiciousZipFile/│   │   ├── Summary.markdown│   │   ├── Logs/│   │   ├── Screenshots/│   │   └── Scripts/│   ├── Scenario-3-MaliciousScriptExecution/│   │   ├── Summary.markdown│   │   ├── Logs/│   │   ├── Screenshots/│   │   └── Scripts/│   ├── Scenario-4-PrivilegeEscalation/│   │   ├── Summary.markdown│   │   ├── Logs/│   │   ├── Screenshots/│   │   └── Scripts/│   ├── Scenario-6-LateralMovement/│   │   ├── Summary.markdown│   │   ├── Logs/│   │   │   ├── sysmon_events_psexec.evtx│   │   │   ├── security_events_psexec.evtx│   │   │   └── wazuh_agent_filtered_psexec.log│   │   ├── Screenshots/│   │   │   ├── attack-command-arch.png│   │   │   ├── wazuh-dashboard-event-logs.png│   │   │   ├── event-logs-psexec.png│   │   │   └── psexec_output.png│   │   ├── attack_script.sh│   │   ├── sysmonconfig-export.xml│   │   └── ossec.conf│   ├── Scenario-7-DataExfiltration/│   │   ├── Summary.markdown│   │   ├── Logs/│   │   │   ├── sysmon_events_exfil.evtx│   │   │   ├── security_events_exfil.evtx│   │   │   └── wazuh_agent_filtered_exfil.log│   │   ├── Screenshots/│   │   │   ├── attack-command-arch.png│   │   │   ├── wazuh-dashboard-event-logs.png│   │   │   ├── event-logs-exfil.png│   │   │   └── smbclient_output.png│   │   ├── attack_script.sh│   │   ├── sysmonconfig-export.xml│   │   └── ossec.conf│   └── Scenario-8-Persistence/│       ├── Summary.markdown│       ├── Logs/│       │   ├── sysmon_events_persist.evtx│       │   ├── security_events_persist.evtx│       │   └── wazuh_agent_filtered_persist.log│       ├── Screenshots/│       │   ├── attack-command-arch.png│       │   ├── wazuh-dashboard-event-logs.png│       │   ├── event-logs-persist.png│       │   └── task_output.png│       ├── attack_script.sh│       ├── sysmonconfig-export.xml│       └── ossec.conf├── Phase3/│   ├── Scenario-1-IncidentResponse/│   │   ├── Summary.markdown│   │   ├── Logs/│   │   ├── Screenshots/│   │   └── Scripts/│   └── Scenario-2-ForensicAnalysis/│       ├── Summary.markdown│       ├── Logs/│       ├── Screenshots/│       └── Scripts/└── README.md

## Phase-wise Tasks
The internship is divided into three phases, each focusing on specific attack scenarios and detection techniques. Below is a summary of tasks completed in **Phase 1** and **Phase 2**, with plans for **Phase 3**.

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
7. **Privilege Abuse** (Attack 4: Create Local User):
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

### Phase 2: Advanced Threat Detection
**Objective**: Simulate advanced attack techniques and enhance detection with custom Wazuh rules.

**Scenarios**:
1. **Beaconing** (Planned):
   - Simulate periodic network connections from Windows VM to a command-and-control server.
   - Detection: Custom Wazuh rule for repetitive network activity (Sysmon Event ID 3).
   - MITRE ATT&CK: T1071.001 (Application Layer Protocol).
2. **Suspicious Zip File** (Planned):
   - Simulate extraction of a malicious zip file containing a payload on Windows VM.
   - Detection: Custom Wazuh rule for file extraction events (Sysmon Event ID 11).
   - MITRE ATT&CK: T1560.001 (Archive Collected Data).
3. **Malicious Script Execution** (Planned):
   - Simulate execution of a malicious PowerShell or VBS script on Windows VM.
   - Detection: Custom Wazuh rule for script execution (Sysmon Event ID 1).
   - MITRE ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell).
4. **Privilege Escalation** (Planned):
   - Simulate exploitation of a vulnerability or misconfiguration to gain elevated privileges.
   - Detection: Custom Wazuh rule for privilege changes (Windows Event ID 4672, Sysmon Event ID 1).
   - MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation).
6. **Lateral Movement** (Completed):
   - Simulated PsExec from Arch Linux (`192.168.1.55`) to execute a command on Windows VM (`192.168.1.101`).
   - Detection: Rule ID `100009` for `psexesvc.exe` (Sysmon Event IDs 1, 3, 11; Security Event ID 4624).
   - Wazuh query: `rule.id:100009 AND agent.name:SIEM-Target-Windows AND sysmon.image:(PsExec.exe OR psexesvc.exe)`.
   - MITRE ATT&CK: T1021.002 (Remote Services: SMB), T1078.003 (Valid Accounts).
7. **Data Exfiltration** (Completed):
   - Simulated SMB file transfer from Windows VM to Arch Linux using `smbclient`.
   - Detection: Rule ID `100011` for SMB access from `192.168.1.55` (Sysmon Event IDs 3, 11; Security Event ID 5145).
   - Wazuh query: `rule.id:100011 AND agent.name:SIEM-Target-Windows AND sysmon.destination_ip:192.168.1.55`.
   - MITRE ATT&CK: T1048.003 (Exfiltration Over C2), T1020 (Automated Exfiltration).
8. **Persistence** (Completed, mapped to Malicious Script Execution context):
   - Simulated scheduled task creation (`MaliciousTask`) on Windows VM via PsExec from Arch Linux, running a malicious script.
   - Detection: Rule ID `100013` for `schtasks.exe` (Sysmon Event IDs 1, 3, 11; Security Event ID 4698).
   - Wazuh query: `rule.id:100013 AND agent.name:SIEM-Target-Windows AND sysmon.image:schtasks.exe AND sysmon.command_line:MaliciousTask`.
   - MITRE ATT&CK: T1053.005 (Scheduled Task), T1078.003 (Valid Accounts).

**Key Deliverables**:
- Custom Wazuh rules (`custom_rules.xml` with IDs `100009`, `100011`, `100013`)
- Scripts (e.g., `attack_script.sh` for PsExec, SMB)
- Logs (Sysmon `.evtx`, Wazuh agent logs)
- Screenshots (Wazuh dashboard, Event Viewer, command outputs)
- Summaries with MITRE ATT&CK mappings

### Phase 3: Incident Response and Reporting (Planned)
**Objective**: Focus on incident response, forensics, and comprehensive reporting for simulated breaches.

**Scenarios** (Tentative):
1. **Incident Response**:
   - Simulate containment and eradication of a detected threat.
   - Detection: Analysis of Wazuh alerts and Sysmon logs.
2. **Forensic Analysis**:
   - Simulate forensic investigation of a compromised system.
   - Detection: Timeline analysis using Sysmon and Windows logs.

**Key Deliverables**:
- Incident response reports
- Forensic analysis logs
- Same directory structure as Phase 1 and 2

**Notes**:
- Each scenario contains:
  - A main summary file (`.markdown`) detailing attack, detection, and learnings.
  - `Logs/` folder with JSON, CSV, or EVTX logs.
  - `Screenshots/` folder with evidence (e.g., Wazuh dashboard, Event Viewer).
  - `Scripts/` folder with simulation scripts (Bash, PowerShell), where applicable.
- Phase 2 folder names follow completed scenarios (e.g., `Scenario-6-LateralMovement`).
- Phase 1 folder naming inconsistencies (e.g., `Logs` vs. `logs`) are preserved.

## Summary
The **DetectAndDefend** internship by **Srida IT** has provided hands-on experience in blue teaming. In **Phase 1**, I completed eight attack scenarios, including **Attack 4: Create Local User**, configuring Sysmon (SwiftOnSecurity) and Wazuh to detect events like brute force, malware, and privilege abuse. In **Phase 2**, I simulated advanced attacks, completing **Lateral Movement**, **Data Exfiltration**, and **Persistence** (mapped to Malicious Script Execution context), with custom Wazuh rules (`100009`, `100011`, `100013`) detecting PsExec, SMB transfers, and scheduled tasks. Planned scenarios for **Beaconing**, **Suspicious Zip File**, **Malicious Script Execution**, and **Privilege Escalation** will further enhance detection capabilities. All findings are documented in the `cyber-intern-phase-1` GitHub repository with logs, screenshots, and MITRE ATT&CK mappings.

Challenges included ensuring Wazuh alert visibility, resolved by updating `ossec.conf` and `custom_rules.xml`. **Phase 3** will focus on incident response and forensics, building on this foundation. This project demonstrates my ability to simulate threats, analyze logs, and document findings, preparing me for a cybersecurity career.

## Acknowledgments
- **Srida IT** for providing the internship and resources.
- **SwiftOnSecurity** for the Sysmon configuration.
- **Wazuh** for the open-source SIEM platform.

## Contact
For inquiries or feedback, please reach out via GitHub or contact Srida IT.

