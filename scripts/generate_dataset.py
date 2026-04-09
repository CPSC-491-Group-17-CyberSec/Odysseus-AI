#!/usr/bin/env python3
"""
generate_dataset.py  –  Extract 38-feature vectors from sample files.

Usage:
    python generate_dataset.py --malware-dir ./samples/malware \
                               --benign-dir  ./samples/benign  \
                               --output      dataset.csv

Each row in the output CSV is:  label, feature_0, feature_1, ..., feature_37
    label = 0 (benign) or 1 (malicious)

Feature extraction mirrors the C++ FeatureExtractor exactly so the trained
model is compatible with the ONNX inference path in the main application.
"""

import argparse
import csv
import math
import os
import struct
import sys
from pathlib import Path
from collections import Counter

# ============================================================================
# Feature names (must match kFeatureNames in FeatureExtractor.h)
# ============================================================================
FEATURE_NAMES = [
    "fileSize_log10", "shannonEntropy", "isExecutable", "isScript", "isDLL",
    "nullByteRatio", "printableAsciiRatio", "highByteRatio", "byteMean",
    "byteStdDev", "controlCharRatio", "whitespaceRatio", "uniqueByteCount",
    "longestNullRun", "entropyFirstQuarter", "entropyLastQuarter",
    "isPE", "peNumSections", "peMaxSectionEntropy", "peCodeSectionRatio",
    "peEntryPointInCode", "peHasDebugInfo", "peImportCount", "peExportCount",
    "peResourceRatio", "peSectionNameAnomaly", "peTimestampAnomaly",
    "peVirtualSizeRatio",
    "stringCount", "stringDensity", "avgStringLength", "maxStringLength",
    "suspiciousStringCount", "urlCount", "ipAddressCount", "registryPathCount",
    "base64StringCount", "hashPartialMatch",
]

NUM_FEATURES = 38

EXE_EXTS = {"exe", "com", "scr", "pif", "msi", "elf", "bin", "app", "out"}
SCRIPT_EXTS = {"bat", "cmd", "ps1", "vbs", "js", "wsh", "wsf", "py", "sh",
               "bash", "pl", "rb", "php", "hta"}
DLL_EXTS = {"dll", "sys", "drv", "ocx", "so", "dylib"}

KNOWN_SECTION_NAMES = {
    ".text", ".rdata", ".data", ".rsrc", ".reloc", ".bss",
    ".idata", ".edata", ".pdata", ".tls", ".debug", ".CRT",
    ".sxdata", ".gfids", ".00cfg", "CODE", "DATA", ".code",
}

SUSPICIOUS_KEYWORDS = [
    "cmd.exe", "powershell", "CreateRemoteThread", "VirtualAlloc",
    "WriteProcessMemory", "NtUnmapViewOfSection", "IsDebuggerPresent",
    "GetProcAddress", "LoadLibrary", "WinExec", "ShellExecute",
    "URLDownloadToFile", "InternetOpen", "HttpSendRequest",
    "RegSetValue", "RegCreateKey", "CreateService", "StartService",
    "OpenProcess", "ReadProcessMemory", "AdjustTokenPrivileges",
    "LookupPrivilegeValue", "CryptEncrypt", "CryptDecrypt",
    "BitBlt", "keybd_event", "GetAsyncKeyState", "SetWindowsHookEx",
    "FindWindow", "EnumProcesses", "Process32First",
    "CreateToolhelp32Snapshot",
]


# ============================================================================
# Entropy
# ============================================================================
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


# ============================================================================
# String extraction
# ============================================================================
def extract_strings(data: bytes, min_len: int = 4):
    strings = []
    current = []
    for b in data:
        if 0x20 <= b <= 0x7E:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []
    if len(current) >= min_len:
        strings.append("".join(current))
    return strings


# ============================================================================
# PE parsing helpers
# ============================================================================
def read_u16(data, off):
    if off + 2 > len(data): return 0
    return struct.unpack_from("<H", data, off)[0]

def read_u32(data, off):
    if off + 4 > len(data): return 0
    return struct.unpack_from("<I", data, off)[0]


# ============================================================================
# Feature extraction (mirrors C++ implementation exactly)
# ============================================================================
def extract_features(file_path: str) -> list[float]:
    try:
        data = Path(file_path).read_bytes()
    except (OSError, PermissionError):
        return []

    if len(data) == 0 or len(data) > 200 * 1024 * 1024:
        return []

    feats = [0.0] * NUM_FEATURES
    ext = Path(file_path).suffix.lstrip(".").lower()
    length = len(data)
    d_len = float(length)

    # --- Pass 1: Metadata + Entropy ---
    feats[0] = math.log10(d_len) if d_len > 0 else 0.0
    feats[1] = shannon_entropy(data)
    feats[2] = 1.0 if ext in EXE_EXTS else 0.0
    feats[3] = 1.0 if ext in SCRIPT_EXTS else 0.0
    feats[4] = 1.0 if ext in DLL_EXTS else 0.0

    # --- Pass 2: Byte Distribution ---
    freq = Counter(data)
    feats[5] = freq.get(0, 0) / d_len  # null ratio
    printable = sum(freq.get(b, 0) for b in range(0x20, 0x7F))
    feats[6] = printable / d_len
    high = sum(freq.get(b, 0) for b in range(0x80, 0x100))
    feats[7] = high / d_len
    mean = sum(b * freq.get(b, 0) for b in range(256)) / d_len
    feats[8] = mean / 255.0
    variance = sum((b - mean) ** 2 * freq.get(b, 0) for b in range(256)) / d_len
    feats[9] = math.sqrt(variance) / 128.0
    ctrl = sum(freq.get(b, 0) for b in range(1, 0x20) if b not in (9, 10, 13))
    feats[10] = ctrl / d_len
    ws = sum(freq.get(b, 0) for b in (0x20, 0x09, 0x0A, 0x0D))
    feats[11] = ws / d_len
    unique = sum(1 for b in range(256) if freq.get(b, 0) > 0)
    feats[12] = unique / 256.0
    # Longest null run
    max_null = cur_null = 0
    for b in data:
        if b == 0:
            cur_null += 1
            max_null = max(max_null, cur_null)
        else:
            cur_null = 0
    feats[13] = max_null / d_len
    # Quarter entropies
    q1 = length // 4
    if q1 > 0:
        feats[14] = shannon_entropy(data[:q1])
    q4_start = length - (length // 4)
    if q4_start < length:
        feats[15] = shannon_entropy(data[q4_start:])

    # --- Pass 3: PE Header ---
    if length >= 64 and data[0:2] == b"MZ":
        pe_offset = read_u32(data, 0x3C)
        if pe_offset + 24 <= length and data[pe_offset:pe_offset+4] == b"PE\x00\x00":
            feats[16] = 1.0  # isPE
            coff = pe_offset + 4
            num_sections = read_u16(data, coff + 2)
            timestamp = read_u32(data, coff + 4)
            opt_header_size = read_u16(data, coff + 16)

            feats[17] = num_sections / 16.0

            opt = coff + 20
            magic = read_u16(data, opt) if opt + 2 <= length else 0
            is64 = (magic == 0x020B)

            entry_rva = 0
            num_data_dirs = 0
            dd_offset = 0

            if is64 and opt + 112 <= length:
                entry_rva = read_u32(data, opt + 16)
                num_data_dirs = read_u32(data, opt + 108)
                dd_offset = 112
            elif not is64 and opt + 96 <= length:
                entry_rva = read_u32(data, opt + 16)
                num_data_dirs = read_u32(data, opt + 92)
                dd_offset = 96

            import_size = resource_size = debug_rva = debug_size = 0
            export_rva = 0
            if dd_offset > 0:
                dd = opt + dd_offset
                if num_data_dirs > 0 and dd + 8 <= length:
                    export_rva = read_u32(data, dd)
                if num_data_dirs > 1 and dd + 16 <= length:
                    import_size = read_u32(data, dd + 12)
                if num_data_dirs > 2 and dd + 24 <= length:
                    resource_size = read_u32(data, dd + 20)
                if num_data_dirs > 6 and dd + 56 <= length:
                    debug_rva = read_u32(data, dd + 48)
                    debug_size = read_u32(data, dd + 52)

            feats[21] = 1.0 if (debug_rva and debug_size) else 0.0
            feats[22] = min((import_size / 20) / 100.0, 1.0) if import_size else 0.0
            feats[23] = 1.0 if export_rva else 0.0
            feats[24] = resource_size / d_len if d_len > 0 else 0.0

            sec_table = opt + opt_header_size
            max_sect_entropy = 0.0
            code_ratio = 0.0
            ep_in_code = False
            name_anomaly = False
            max_virt_raw = 0.0

            for s in range(num_sections):
                off = sec_table + s * 40
                if off + 40 > length:
                    break
                name = data[off:off+8].split(b"\x00")[0].decode("ascii", errors="ignore")
                virt_size = read_u32(data, off + 8)
                virt_addr = read_u32(data, off + 12)
                raw_size = read_u32(data, off + 16)
                raw_offset = read_u32(data, off + 20)
                chars = read_u32(data, off + 36)

                if raw_offset > 0 and raw_size > 0 and raw_offset + raw_size <= length:
                    se = shannon_entropy(data[raw_offset:raw_offset+raw_size])
                    max_sect_entropy = max(max_sect_entropy, se)

                is_code = (chars & 0x20) != 0
                if is_code:
                    code_ratio = raw_size / d_len
                    if virt_addr <= entry_rva < virt_addr + virt_size:
                        ep_in_code = True

                if name and name not in KNOWN_SECTION_NAMES:
                    name_anomaly = True

                if raw_size > 0:
                    ratio = virt_size / raw_size
                    max_virt_raw = max(max_virt_raw, ratio)

            feats[18] = max_sect_entropy / 8.0
            feats[19] = code_ratio
            feats[20] = 1.0 if ep_in_code else 0.0
            feats[25] = 1.0 if name_anomaly else 0.0
            feats[26] = 1.0 if (timestamp > 0 and (timestamp < 631152000 or timestamp > 1893456000)) else 0.0
            feats[27] = min(max_virt_raw / 10.0, 1.0)

    # --- Pass 4: Strings + Hash ---
    strings = extract_strings(data)
    if strings:
        feats[28] = math.log10(len(strings) + 1)
        total_str_bytes = sum(len(s) for s in strings)
        feats[29] = total_str_bytes / d_len
        feats[30] = min((total_str_bytes / len(strings)) / 100.0, 1.0)
        feats[31] = min(max(len(s) for s in strings) / 500.0, 1.0)

        susp = url = ip = reg = b64 = 0
        for s in strings:
            if any(kw in s for kw in SUSPICIOUS_KEYWORDS):
                susp += 1
            if "http://" in s or "https://" in s:
                url += 1
            # Simple IP check
            parts = s.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p.isdigit()):
                ip += 1
            if any(x in s for x in ("HKEY_", "HKLM\\", "HKCU\\", "SOFTWARE\\", "CurrentVersion\\Run")):
                reg += 1
            if len(s) > 40:
                alpha = sum(1 for c in s if c.isalnum() or c in "+/=")
                if alpha / len(s) > 0.90:
                    b64 += 1

        feats[32] = min(susp / 10.0, 1.0)
        feats[33] = min(url / 5.0, 1.0)
        feats[34] = min(ip / 5.0, 1.0)
        feats[35] = min(reg / 5.0, 1.0)
        feats[36] = min(b64 / 5.0, 1.0)

    feats[37] = 0.0  # hashPartialMatch placeholder
    return feats


# ============================================================================
# Main – walk directories and build CSV
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description="Generate feature dataset for Odysseus AI training")
    parser.add_argument("--malware-dir", required=True, help="Directory of malware samples")
    parser.add_argument("--benign-dir", required=True, help="Directory of benign files")
    parser.add_argument("--output", default="dataset.csv", help="Output CSV path")
    args = parser.parse_args()

    rows = []

    for label, directory in [(1, args.malware_dir), (0, args.benign_dir)]:
        if not os.path.isdir(directory):
            print(f"Warning: {directory} does not exist, skipping")
            continue

        count = 0
        for root, dirs, files in os.walk(directory):
            for fname in files:
                fpath = os.path.join(root, fname)
                feats = extract_features(fpath)
                if feats:
                    rows.append([label] + feats)
                    count += 1
                    if count % 100 == 0:
                        print(f"  [{label}] Processed {count} files...")

        print(f"Label {label}: extracted {count} feature vectors from {directory}")

    if not rows:
        print("No features extracted. Check your input directories.")
        sys.exit(1)

    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["label"] + FEATURE_NAMES)
        writer.writerows(rows)

    print(f"Dataset written to {args.output} ({len(rows)} samples)")


if __name__ == "__main__":
    main()
