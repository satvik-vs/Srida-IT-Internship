# Attack 2: Suspicious PowerShell Usage Simulation
Write-Host "Simulating Suspicious PowerShell Usage..."
powershell -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACIAcwBtAG8AYwBoAC4AZQB4AGUAIgA=
Write-Host "Suspicious PowerShell Simulation Complete"
# Expected: Sysmon Event ID 1 (powershell.exe)
# Wazuh: Search "win.eventdata.image:powershell.exe" and "win.eventdata.commandLine:smoch.exe"