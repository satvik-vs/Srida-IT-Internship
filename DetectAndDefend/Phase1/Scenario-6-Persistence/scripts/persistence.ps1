# Attack 9: Simulate Persistence Simulation
Write-Host "Simulating Persistence via Startup Folder..."
# Create a benign test file (copy notepad.exe as evil.exe)
$testFile = "C:\Users\Public\evil.exe"
Copy-Item -Path "C:\Windows\System32\notepad.exe" -Destination $testFile
# Copy to Startup folder
$startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Copy-Item -Path $testFile -Destination "$startupFolder\evil.exe"
Write-Host "Persistence Simulation Complete"
# Expected: Sysmon Event ID 11 (file creation in Startup folder)
# Wazuh: Search "event.code:11" and "win.eventdata.targetFilename:*Startup\\evil.exe"