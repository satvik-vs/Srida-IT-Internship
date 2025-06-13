# Attack 5: Registry Modification Simulation
Write-Host "Simulating Registry Modification..."
# Create temp directory if it doesn't exist
New-Item -Path "C:\temp" -ItemType Directory -Force
# Set registry Run key to point to fake malware
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "evil" -Value "C:\temp\malware.exe"
Write-Host "Registry Modification Simulation Complete"
# Expected: Sysmon Event ID 13 (registry value set)
# Wazuh: Search "event.code:13" and "win.eventdata.targetObject:*Run\\evil"