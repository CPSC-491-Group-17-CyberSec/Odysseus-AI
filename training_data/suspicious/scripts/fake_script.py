#!/usr/bin/env python3
"""
SAFE SIMULATION FILE — NOT REAL MALWARE
========================================
This script simulates suspicious behavior patterns that malware
commonly exhibits. It is designed for training Odysseus-AI's
anomaly detector and will NOT cause any harm when executed.

All "malicious" operations are commented out or use harmless
substitutes (print statements, dummy variables).
"""

import base64
import os
import sys

# ---- Suspicious pattern: base64-encoded commands ----
# In real malware, this would decode and execute a payload
encoded_command = base64.b64encode(b"echo 'This is a harmless test'").decode()
decoded_command = base64.b64decode(encoded_command).decode()
print(f"[DEMO] Decoded command: {decoded_command}")

# ---- Suspicious pattern: environment fingerprinting ----
# Malware often checks the environment before executing
hostname = os.environ.get("HOSTNAME", "unknown")
username = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
platform_info = sys.platform
print(f"[DEMO] Host: {hostname}, User: {username}, Platform: {platform_info}")

# ---- Suspicious pattern: network-like strings ----
# These look like C2 server addresses but go nowhere
C2_SERVERS = [
    "http://192.168.1.100:4444/beacon",
    "http://10.0.0.50:8080/callback",
    "https://evil-c2.example.com/register",
]
print(f"[DEMO] Would connect to: {C2_SERVERS[0]} (NOT actually connecting)")

# ---- Suspicious pattern: file system enumeration ----
# Malware scans for valuable files; we just print the concept
TARGET_EXTENSIONS = [".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt"]
print(f"[DEMO] Would search for: {TARGET_EXTENSIONS}")

# ---- Suspicious pattern: persistence mechanism reference ----
# References to auto-start registry keys (Windows malware pattern)
PERSISTENCE_KEYS = [
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
]
print(f"[DEMO] Persistence targets: {PERSISTENCE_KEYS[0]}")

# ---- Suspicious pattern: process injection references ----
# API names commonly associated with process injection
SUSPICIOUS_APIS = [
    "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "OpenProcess", "VirtualAllocEx",
    "LoadLibrary", "GetProcAddress", "WinExec", "ShellExecute",
]
print(f"[DEMO] References suspicious APIs: {SUSPICIOUS_APIS[:3]}")

# ---- Suspicious pattern: encoded payload blocks ----
# Multiple base64 blocks that simulate staged delivery
STAGES = {
    "stage1": base64.b64encode(b"print('Stage 1: Reconnaissance')").decode(),
    "stage2": base64.b64encode(b"print('Stage 2: Privilege Escalation')").decode(),
    "stage3": base64.b64encode(b"print('Stage 3: Data Exfiltration')").decode(),
}

for name, payload in STAGES.items():
    decoded = base64.b64decode(payload).decode()
    print(f"[DEMO] {name}: {decoded}")

# ---- Suspicious pattern: anti-analysis checks ----
# Malware checks for sandboxes/debuggers
def check_sandbox():
    """DEMO: Simulates sandbox detection (always returns False)."""
    sandbox_indicators = [
        "VBOX", "VMWARE", "SANDBOX", "MALWARE", "VIRUS",
    ]
    current_hostname = os.environ.get("COMPUTERNAME", "").upper()
    # In real malware, this would check and exit. We just log.
    for indicator in sandbox_indicators:
        if indicator in current_hostname:
            print(f"[DEMO] Sandbox detected: {indicator}")
            return True
    return False

print(f"[DEMO] Sandbox check result: {check_sandbox()}")

# ---- Suspicious pattern: download URL construction ----
def build_download_url(host, port, path):
    """DEMO: Builds URL that LOOKS like a malware download endpoint."""
    return f"http://{host}:{port}/{path}"

url = build_download_url("192.168.1.100", "4444", "payload.exe")
print(f"[DEMO] Download URL: {url} (NOT downloading anything)")

print("\n[SAFE] This script completed without performing any harmful actions.")
print("[SAFE] It exists solely to train the Odysseus-AI anomaly detector.")
