# Attack 10: Create Local User Simulation
Write-Host "Simulating Local User Creation and Privilege Abuse..."
# Create local user
net user attacker P@ssword123 /add
# Add user to Administrators group
net localgroup administrators attacker /add
Write-Host "Local User Creation Simulation Complete"
# Expected: Windows Event ID 4720 (user creation), 4732 (group change), Sysmon Event ID 1 (net.exe)
# Wazuh: Search "event.code:4720 OR event.code:4732" or "win.eventdata.image:net.exe"