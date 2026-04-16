#!/usr/bin/env python3
"""Simple health check script for Odysseus-AI services."""

import sys
import json
import urllib.request
import urllib.error

SERVICES = {
    "scanner": "http://localhost:8080/api/v1/health",
    "ollama": "http://localhost:11434/api/tags",
}

def check_service(name, url, timeout=5):
    """Check if a service is responding."""
    try:
        req = urllib.request.urlopen(url, timeout=timeout)
        data = req.read().decode('utf-8')
        return True, f"OK (HTTP {req.status})"
    except urllib.error.URLError as e:
        return False, f"FAIL ({e.reason})"
    except Exception as e:
        return False, f"ERROR ({e})"

def main():
    print("Odysseus-AI Health Check")
    print("=" * 40)
    
    all_ok = True
    results = {}
    
    for name, url in SERVICES.items():
        ok, status = check_service(name, url)
        results[name] = {"healthy": ok, "status": status}
        indicator = "OK" if ok else "FAIL"
        print(f"  [{indicator:4s}] {name:12s}: {status}")
        if not ok:
            all_ok = False
    
    print()
    if all_ok:
        print("All services healthy.")
    else:
        print("WARNING: Some services are down.")
        sys.exit(1)

if __name__ == "__main__":
    main()
