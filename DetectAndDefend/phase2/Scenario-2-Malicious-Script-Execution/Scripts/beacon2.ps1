while ($true) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient("192.168.1.55", 8080)
        $stream = $client.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.WriteLine("Beacon from $env:COMPUTERNAME at $(Get-Date)")
        $writer.Flush()
        $stream.Close()
        $client.Close()
    } catch {}
    Start-Sleep -Seconds 03
}
