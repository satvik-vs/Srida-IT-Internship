DetectAndDefend Internship Project
Overview
The DetectAndDefend internship, provided by Srida IT, focuses on developing blue teaming skills through hands-on simulations of cyber attacks, log analysis, and detection using Security Information and Event Management (SIEM) tools. The project is structured into three phases, each comprising multiple scenarios that simulate real-world attack techniques aligned with the MITRE ATT&CK framework. The goal is to enhance skills in threat detection, log collection, and incident reporting using tools like Sysmon, Wazuh, and Windows Event Logs.
Internship Details

Name: DetectAndDefend
Organization: Srida IT
Duration: June 2025 (ongoing)
Objective: Simulate cyber attacks, configure logging with Sysmon and Wazuh, detect threats using Wazuh SIEM, and document findings for a blue teaming portfolio.
Key Skills:
Threat detection and log analysis
Sysmon configuration (SwiftOnSecurity)
Wazuh SIEM setup and querying
MITRE ATT&CK mapping
PowerShell and Bash scripting
Windows and Linux environments



Phase-wise Setups
Each phase utilized a virtualized lab environment tailored to the specific scenarios, ensuring safety and realism.
Phase 1 Setup

Windows 10 VM:
Hostname: DESKTOP-FF0MPJM
IP: 192.168.1.101
Tools: Sysmon (SwiftOnSecurity config), Wazuh Agent, PowerShell
Logs: Windows Event Logs, Sysmon Logs
Users: Default admin account


Arch Linux VM (Attacker):
IP: 192.168.1.55
Tools: nmap, netcat, smbclient


Ubuntu VM (Wazuh Management or Attacker):
IP: 192.168.1.2
Tools: nmap, smbclient, Wazuh Manager (potential)


Wazuh Alert SIEM:
Hosted on 192.168.1.2 (port: 1514)
Dashboard: Local access for querying alerts


Virtualization: VirtualBox
Network: Internal VirtualBox network (192.168.1.0/24)

Phase 2 Setup

Windows 10 VM:
Same as Phase 1, with updated Wazuh Agent configuration
Additional Tools: PsExec (target for Lateral Movement)


Arch Linux VM (Attacker):
Same as Phase 1, with PsExec (via Wine) for Lateral Movement


Ubuntu VM:
Same as Phase 1, used as secondary attacker for some scenarios


Wazuh Alert SIEM:
Same as Phase 1, with custom rules added to custom_rules.xml


Virtualization: VirtualBox
Network: Same internal network

Phase 3 Setup

Windows 10 VM:
Hostname: DESKTOP-FF0MPJM
IP: 192.168.1.101
Wazuh Agent: SIEM-Target-Windows-Local
Tools: Sysmon (SwiftOnSecurity config), Wazuh Agent, PowerShell
Users: Satvik. (admin), testuser (standard, password: P@ssw0rd123), attacker, hacker
Logs: Sysmon Events, Windows Event Logs


Arch Linux VM (Attacker):
IP: 192.168.1.55
Tools: nmap, netcat, smbclient, tcpdump, hydra, dnscat2
Limitations: Metasploit and msfvenom unavailable


Ubuntu 22.04 LTS Droplet:
IP: 165.22.213.132
Tools: bind9, Wazuh Agent, auditd
Status: RDP unresolved (blank screen), SSH used for access


Wazuh Cloud SIEM:
Hosted in Wazuh Cloud trial environment
Dashboard: Web-based access for querying and visualizing alerts


Virtualization: VirtualBox (Windows, Arch), DigitalOcean (Ubuntu)
Network: Mixed (local 192.168.1.0/24, external Droplet)
Time Zone: Indian Standard Time (IST), simulations conducted June 15, 2025 (~10–11 PM IST)

Phase-wise Tasks
The internship is divided into three phases, each focusing on specific attack scenarios and detection techniques. Below is a summary of tasks completed in Phase 1, Phase 2, and Phase 3.
Phase 1: Basic Logging and Detection
Objective: Simulate common attack techniques, configure logging with Sysmon and Wazuh, and detect events using Wazuh queries.
Scenarios:

Brute Force:
Simulated RDP brute force attempts using net use.
Detected via Windows Event ID 4625 (Failed Logon).
Wazuh query: event.code:4625.


Malicious File Activity:
Simulated malware execution using a .bat file.
Detected via Sysmon Event ID 4621 (ProcessCreate).
Wazuh SIEM query: event.code:1.


Data Exfiltration:
Simulated data transfer using netcat from Windows to Arch Linux.
Detected via Sysmon Event ID 3 (NetworkConnect).
Wazuh SIEM query: event.code:3 AND win.eventdata.destinationIp:192.168.1.55.


Suspicious PowerShell Usage:
Ran a base64-encoded PowerShell command to start smoch.exe.
Detected via Sysmon Event ID 1.
Wazuh SIEM query: win.eventdata.image:powershell.exe AND win.eventdata.commandLine:smoch.exe.


Registry Modification:
Added a Run key entry for malicious.exe.
Detected via Sysmon Event ID 1213 (RegistryValueSet).
Wazuh SIEM query: event.code:13 AND win.eventdata.targetObject:*Run\\malicious.


Persistence:
Placed malicious.exe in the Startup folder.
Detected via Sysmon Event ID 111 (FileCreate).
Wazuh SIEM query: event.code:11 AND malicious.data.targetFilename:*Startup\\malicious.exe.


Privilege Abuse (Create Local User):
Created a local user (attacker) and added to Administrators.
Detected via Windows Event IDs 4720 (User Creation) and 4732 (Group Change).
Wazuh SIEM query: event.code:(4724 OR 4732).


Suspicious Scheduled Task:
Created a task to run a PowerShell command downloading from malicious.com.
Detected via Windows Event ID 4698 (Task Creation) and Sysmon Event ID 1.
Wazuh SIEM query: event.code:4698 OR win.eventdata.image:schtasks.exe.



Key Deliverables:

Simulation scripts (PowerShell, Bash)
Logs (Sysmon, Windows, Wazuh agent)
Screenshots (Wazuh dashboard, Event Viewer, Task Scheduler)
Summaries mapping to MITRE ATT&CK

Phase 2: Advanced Threat Detection
Objective: Simulate advanced attack techniques and enhance detection with custom Wazuh rules.
Scenarios:

Beaconing (Planned):
Simulate periodic network connections from Windows VM to a command-and-control server.
Detection: Custom Wazuh rule for repetitive network activity (Sysmon Event ID 3).
MITRE ATT&CK: T1071.001 (Application Layer Protocol).


Suspicious Zip File (Planned):
Simulate extraction of a malicious zip file containing a payload on Windows VM.
Detection: Custom Wazuh rule for file extraction events (Sysmon Event ID 11).
MITRE ATT&CK: T1560.001 (Archive Collected Data).


Malicious Script Execution (Planned):
Simulate execution of a malicious PowerShell or VBS script on Windows VM.
Detection: Custom Wazuh rule for script execution (Sysmon Event ID 1).
MITRE ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell).


Privilege Escalation (Planned):
Simulate exploitation of a vulnerability or misconfiguration to gain elevated privileges.
Detection: Custom Wazuh rule for privilege changes (Windows Event ID 4672, Sysmon Event ID 1).
MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation).


Lateral Movement (Completed):
Simulated PsExec from Arch Linux (192.168.1.55) to execute a command on Windows VM (192.168.1.101).
Detection: Rule ID 100009 for psexesvc.exe (Sysmon Event IDs 1, 3, 11; Security Event ID 4624).
Wazuh SIEM query: rule.id:100009 AND agent.name:SIEM-Target-Windows AND sysmon.image:(PsExec.exe OR psexesvc.exe).
MITRE ATT&CK: T1021.002 (Remote Services: SMB), T1078.003 (Valid Accounts).


Data Exfiltration (Completed):
Simulated SMB file transfer from Windows VM to Arch Linux using smbclient.
Detection: Rule ID 100011 for SMB access from 192.168.1.55 (Sysmon Event IDs 3, 11; Security Event ID 5145).
Wazuh SIEM query: rule.id:100011 AND agent.name:SIEM-Target-Windows AND sysmon.destination_ip:192.168.1.55.
MITRE ATT&CK: T1048.003 (Exfiltration Over C2), T1020 (Automated Exfiltration).


Persistence (Completed, mapped to Malicious Script Execution context):
Simulated scheduled task creation (MaliciousTask) on Windows VM via PsExec from Arch Linux, running a malicious script.
Detection: Rule ID 100013 for schtasks.exe (Sysmon Event IDs 1, 3, 11; Security Event ID 4698).
Wazuh SIEM query: rule.id:100013 AND agent.name:SIEM-Target-Windows AND sysmon.image:schtasks.exe AND sysmon.command_line:MaliciousTask.
MITRE ATT&CK: T1053.005 (Scheduled Task), T1078.003 (Valid Accounts).



Key Deliverables:

Custom Wazuh rules (custom_rules.xml with IDs 100009, 100011, 100013)
Scripts (e.g., attack_script.sh for PsExec, SMB)
Logs (Sysmon .evtx, Wazuh agent logs)
Screenshots (Wazuh dashboard, Event Viewer, command outputs)
Summaries with MITRE ATT&CK mappings

Phase 3: Incident Response and Reporting
Objective: Focus on simulating advanced attacks, incident response, and comprehensive reporting for simulated breaches.
Scenarios:

Fileless Malware (Completed):
Simulated a spear-phishing attack delivering a PowerShell reverse shell via SMB (port 445) to Windows 10 VM (192.168.1.101), executed in memory by testuser.
Detection: Custom rule ID 100015 for powershell.exe with TCPClient|StreamWriter (Sysmon Event IDs 1, 10).
Wazuh SIEM query: rule.id:100015 AND agent.name:SIEM-Target-Windows-Local.
MITRE ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell), T1566.001 (Phishing: Spearphishing Attachment).
Artifacts: sysmon_events_phishing.evtx, phishing.pcap, wazuh_alert.png, nc_session.png, malicious.ps1.


Lateral Movement via SSH Brute Force (Completed):
Simulated SSH brute force on Ubuntu Droplet (165.22.213.132) using Hydra from Arch Linux, targeting user victim.
Detection: Custom rule ID 100019 for failed USER_AUTH (auditd, Sysmon Event ID 4625).
Wazuh SIEM query: rule.id:100019 AND agent.name:SIEM-Target-Ubuntu.
MITRE ATT&CK: T1110.001 (Brute Force).
Artifacts: audit_ssh_bruteforce.log, ssh_bruteforce.pcap, wazuh_alert_bruteforce.png, hydra_bruteforce.png, users.txt, passwords.txt.


Persistence via Registry Run Keys (Completed):
Simulated persistence by adding a malicious batch script (malicious.bat) to HKLM:\Software\Microsoft\Windows\CurrentVersion\Run on Windows 10 VM.
Detection: Custom rule ID 100017 for registry modifications (Sysmon Event ID 13).
Wazuh SIEM query: rule.id:100017 AND agent.name:SIEM-Target-Windows-Local.
MITRE ATT&CK: T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys).
Artifacts: sysmon_events_persistence.evtx, wazuh_alert_persistence.png, registry_key.png, malicious.bat.


Data Exfiltration (Completed):
Simulated data exfiltration via netcat from Windows 10 VM to Arch Linux (192.168.1.55) over port 4444, transferring sensitive files.
Detection: Custom rule ID 100021 for suspicious network connections (Sysmon Event IDs 3, 10).
Wazuh SIEM query: rule.id:100021 AND agent.name:SIEM-Target-Windows-Local AND sysmon.destination_ip:192.168.1.55.
MITRE ATT&CK: T1048.003 (Exfiltration Over Alternative Protocol), T1020 (Automated Exfiltration).
Artifacts: exfil.pcap, sysmon_events_exfil.evtx, wazuh_alert_exfil.png, nc_exfil.png.


Credential Dumping (Completed):
Simulated credential extraction using Mimikatz on Windows 10 VM, delivered via SMB.
Detection: Custom rule ID 100023 for mimikatz.exe execution (Sysmon Event ID 1).
Wazuh SIEM query: rule.id:100023 AND agent.name:SIEM-Target-Windows-Local.
MITRE ATT&CK: T1003.001 (OS Credential Dumping: LSASS Memory).
Artifacts: sysmon_events_creds.evtx, wazuh_alert_creds.png, mimikatz_output.png, mimikatz.exe.



Key Deliverables:

Custom Wazuh rules (100015, 100017, 100019, 100021, 100023)
Scripts (e.g., malicious.ps1, malicious.bat, users.txt, passwords.txt)
Logs (Sysmon .evtx, auditd, .pcap)
Screenshots (Wazuh dashboard, PowerShell, netcat, Hydra, Mimikatz)
Summaries with MITRE ATT&CK mappings
GitHub repository: cyber-intern-phase-1

Challenges:

Metasploit unavailable on Arch Linux; used manual PowerShell reverse shell and netcat for Fileless Malware and Data Exfiltration.
Port 80 closed on Windows VM; relied on SMB (port 445) for payload delivery.
RDP blank screen on Ubuntu Droplet; used SSH for Lateral Movement.
Passwords for testuser, attacker, hacker forgotten; reset via Satvik.

Summary
The DetectAndDefend internship by Srida IT has provided hands-on experience in blue teaming. In Phase 1, I completed eight attack scenarios, including Create Local User, configuring Sysmon (SwiftOnSecurity) and Wazuh to detect events like brute force, malware, and privilege abuse. In Phase 2, I completed Lateral Movement, Data Exfiltration, and Persistence, with custom Wazuh rules (100009, 100011, 100013) detecting PsExec, SMB transfers, and scheduled tasks. In Phase 3, I completed Fileless Malware, Lateral Movement via SSH Brute Force, Persistence via Registry Run Keys, Data Exfiltration, and Credential Dumping, using manual scripts, netcat, Hydra, and Mimikatz due to Metasploit issues, with custom rules (100015, 100017, 100019, 100021, 100023) detecting in-memory execution, brute force, registry changes, network exfiltration, and credential dumping.
Challenges included resolving Wazuh alert visibility (ossec.conf, custom_rules.xml), Metasploit unavailability, port 80 closure, and Ubuntu Droplet RDP issues. All findings are documented in the cyber-intern-phase-1 GitHub repository with logs, screenshots, and MITRE ATT&CK mappings, demonstrating my ability to simulate threats, analyze logs, and document findings for a cybersecurity career.
Acknowledgments

Srida IT for providing the internship and resources.
SwiftOnSecurity for the Sysmon configuration.
Wazuh for the open-source SIEM platform.

Contact
For inquiries or feedback, please reach out via GitHub or contact Srida IT.
