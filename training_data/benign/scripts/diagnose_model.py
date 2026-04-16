#!/usr/bin/env python3
"""
diagnose_model.py  –  Diagnose the ONNX anomaly detection pipeline.

Run this against a directory of known-benign files to determine whether
the scoring problem is in the model, the calibration, or the classification.

Usage:
    python diagnose_model.py --model ../data/anomaly_model.onnx \
                              --benign-dir ./validation_benign

This script:
  1. Extracts features from each file (using the same Python extractor
     that was used for training, so features are guaranteed compatible)
  2. Runs ONNX inference and prints:
     - raw output tensor(s) shape and values
     - p(benign) and p(malicious)
  3. Summarizes the score distribution across all files
  4. Diagnoses which failure case applies (A, B, or C)

Requires:
    pip install numpy onnxruntime
"""

import argparse
import os
import sys
import math
import struct
from pathlib import Path
from collections import Counter

import numpy as np

# ============================================================================
# Feature extraction (copied from generate_dataset.py to stay in sync)
# ============================================================================

EXE_EXTS = {"exe", "com", "scr", "pif", "msi", "elf", "bin", "app", "out"}
SCRIPT_EXTS = {"bat", "cmd", "ps1", "vbs", "js", "wsh", "wsf", "py", "sh",
               "bash", "pl", "rb", "php", "hta"}
DLL_EXTS = {"dll", "sys", "drv", "ocx", "so", "dylib"}

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


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


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


def read_u16(data, off):
    if off + 2 > len(data): return 0
    return struct.unpack_from("<H", data, off)[0]

def read_u32(data, off):
    if off + 4 > len(data): return 0
    return struct.unpack_from("<I", data, off)[0]

KNOWN_SECTION_NAMES = {
    ".text", ".rdata", ".data", ".rsrc", ".reloc", ".bss",
    ".idata", ".edata", ".pdata", ".tls", ".debug", ".CRT",
    ".sxdata", ".gfids", ".00cfg", "CODE", "DATA", ".code",
}


def extract_features(file_path: str) -> list[float]:
    try:
        data = Path(file_path).read_bytes()
    except (OSError, PermissionError):
        return []

    if len(data) == 0 or len(data) > 200 * 1024 * 1024:
        return []

    feats = [0.0] * 38
    ext = Path(file_path).suffix.lstrip(".").lower()
    length = len(data)
    d_len = float(length)

    # Pass 1
    feats[0] = math.log10(d_len) if d_len > 0 else 0.0
    feats[1] = shannon_entropy(data)
    feats[2] = 1.0 if ext in EXE_EXTS else 0.0
    feats[3] = 1.0 if ext in SCRIPT_EXTS else 0.0
    feats[4] = 1.0 if ext in DLL_EXTS else 0.0

    # Pass 2
    freq = Counter(data)
    feats[5] = freq.get(0, 0) / d_len
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
    max_null = cur_null = 0
    for b in data:
        if b == 0:
            cur_null += 1
            max_null = max(max_null, cur_null)
        else:
            cur_null = 0
    feats[13] = max_null / d_len
    q1 = length // 4
    if q1 > 0:
        feats[14] = shannon_entropy(data[:q1])
    q4_start = length - (length // 4)
    if q4_start < length:
        feats[15] = shannon_entropy(data[q4_start:])

    # Pass 3: PE
    if length >= 64 and data[0:2] == b"MZ":
        pe_offset = read_u32(data, 0x3C)
        if pe_offset + 24 <= length and data[pe_offset:pe_offset+4] == b"PE\x00\x00":
            feats[16] = 1.0
            coff = pe_offset + 4
            num_sections = read_u16(data, coff + 2)
            timestamp = read_u32(data, coff + 4)
            opt_header_size = read_u16(data, coff + 16)
            feats[17] = num_sections / 16.0

            opt = coff + 20
            magic = read_u16(data, opt) if opt + 2 <= length else 0
            is64 = (magic == 0x020B)
            entry_rva = num_data_dirs = 0
            dd_offset = 0

            if is64 and opt + 112 <= length:
                entry_rva = read_u32(data, opt + 16)
                num_data_dirs = read_u32(data, opt + 108)
                dd_offset = 112
            elif not is64 and opt + 96 <= length:
                entry_rva = read_u32(data, opt + 16)
                num_data_dirs = read_u32(data, opt + 92)
                dd_offset = 96

            import_size = resource_size = debug_rva = debug_size = export_rva = 0
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
            max_sect_entropy = code_ratio = 0.0
            ep_in_code = name_anomaly = False
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

    # Pass 4: Strings
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

    feats[37] = 0.0
    return feats


# ============================================================================
# ONNX Diagnosis
# ============================================================================

def diagnose(model_path: str, benign_dir: str, verbose: bool = True):
    import onnxruntime as ort

    sess = ort.InferenceSession(model_path)
    input_name = sess.get_inputs()[0].name

    print(f"Model: {model_path}")
    print(f"Inputs:  {[(i.name, i.shape, i.type) for i in sess.get_inputs()]}")
    print(f"Outputs: {[(o.name, o.shape, o.type) for o in sess.get_outputs()]}")
    print()

    results = []
    skipped = 0

    for root, dirs, files in os.walk(benign_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            feats = extract_features(fpath)
            if not feats:
                skipped += 1
                continue

            X = np.array([feats], dtype=np.float32)
            outs = sess.run(None, {input_name: X})

            # Extract probabilities
            if len(outs) >= 2:
                probs = np.array(outs[1])
                if probs.ndim >= 2 and probs.shape[-1] >= 2:
                    p_benign = float(probs[0, 0])
                    p_malicious = float(probs[0, 1])
                else:
                    p_benign = 0.0
                    p_malicious = float(probs.flat[0])
            else:
                p_benign = 0.0
                p_malicious = float(outs[0].flat[0])

            label_out = int(outs[0].flat[0]) if len(outs) >= 2 else -1
            ext = Path(fpath).suffix.lower()

            results.append({
                'file': fname,
                'ext': ext,
                'p_benign': p_benign,
                'p_malicious': p_malicious,
                'label': label_out,
                'entropy': feats[1],
                'printable_ascii': feats[6],
                'high_bytes': feats[7],
                'isPE': feats[16],
                'susp_apis': feats[32],
                'urls': feats[33],
                'base64': feats[36],
            })

            if verbose:
                print(f"  {fname:40s}  ext={ext:6s}  "
                      f"p(mal)={p_malicious:.6f}  p(ben)={p_benign:.6f}  "
                      f"label={label_out}  "
                      f"entropy={feats[1]:.2f}  ascii={feats[6]:.2f}  "
                      f"highB={feats[7]:.2f}")

    if not results:
        print("No files processed!")
        return

    # ── Summary Statistics ─────────────────────────────────────────────────
    scores = [r['p_malicious'] for r in results]
    scores_arr = np.array(scores)

    print(f"\n{'='*70}")
    print(f"DIAGNOSIS SUMMARY  ({len(results)} benign files, {skipped} skipped)")
    print(f"{'='*70}")
    print(f"  p(malicious) distribution for KNOWN-BENIGN files:")
    print(f"    Min:    {scores_arr.min():.6f}")
    print(f"    Max:    {scores_arr.max():.6f}")
    print(f"    Mean:   {scores_arr.mean():.6f}")
    print(f"    Median: {np.median(scores_arr):.6f}")
    print(f"    Std:    {scores_arr.std():.6f}")
    print(f"    >0.90:  {(scores_arr > 0.90).sum()}/{len(scores_arr)}")
    print(f"    >0.99:  {(scores_arr > 0.99).sum()}/{len(scores_arr)}")
    print(f"    <0.50:  {(scores_arr < 0.50).sum()}/{len(scores_arr)}")
    print(f"    <0.10:  {(scores_arr < 0.10).sum()}/{len(scores_arr)}")

    # ── Diagnosis ──────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("FAILURE MODE DIAGNOSIS")
    print(f"{'='*70}")

    if scores_arr.std() < 0.05 and scores_arr.mean() > 0.90:
        print("""
  >>> CASE A: MODEL / TRAINING DATA ISSUE <<<

  The raw ONNX model outputs are all compressed near {:.4f} with
  std={:.4f} for known-benign files.  The model does not meaningfully
  distinguish benign files from malicious ones.

  ROOT CAUSE: The model was likely trained on synthetic data that does
  not represent the diversity of real-world benign files.  The training
  set only contained synthetic PE executables and text documents.  Real
  HTML, CSS, JS, JPG, PDF, ZIP files look completely foreign to the
  model, so it classifies them as malicious with high confidence.

  SOLUTION:
  1. Retrain the model with REAL benign files (see below)
  2. Include diverse file types: .html, .css, .js, .jpg, .png, .pdf,
     .zip, .py, .cpp, .md, .json, .xml, etc.
  3. Ensure at least 200-500 benign samples per file type
  4. Use the generate_dataset.py script with real file directories
""".format(scores_arr.mean(), scores_arr.std()))

    elif scores_arr.std() < 0.05 and scores_arr.mean() < 0.10:
        print("""
  >>> CASE A (inverted): MODEL OUTPUTS ALL LOW <<<

  The model outputs near-zero for all files.  It may have learned
  to always predict "benign", possibly due to class imbalance in
  the training data.
""")

    elif scores_arr.std() > 0.15:
        # Scores vary — check if the classification is the problem
        above_threshold = (scores_arr > 0.50).sum()
        pct = above_threshold / len(scores_arr) * 100
        if pct > 70:
            print(f"""
  >>> CASE B or C: SCORES VARY (std={scores_arr.std():.3f}) BUT {pct:.0f}% ABOVE THRESHOLD <<<

  The model produces varying scores, but the threshold is too low
  for the actual score distribution of benign files.

  You may need to:
  1. Raise the base threshold
  2. Adjust calibration curves
  3. Retrain with more diverse benign data
""")
        else:
            print(f"""
  >>> LOOKS REASONABLE: SCORES VARY, {pct:.0f}% ABOVE THRESHOLD <<<

  The model produces varying scores with good separation.
  The issue may be in the classification logic, not the model.
""")
    else:
        print(f"""
  >>> INCONCLUSIVE: std={scores_arr.std():.3f}, mean={scores_arr.mean():.3f} <<<

  Run with more files for a clearer diagnosis.
""")

    # ── Per-extension breakdown ────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("PER-EXTENSION BREAKDOWN")
    print(f"{'='*70}")
    exts = {}
    for r in results:
        e = r['ext'] or '(none)'
        exts.setdefault(e, []).append(r['p_malicious'])

    for e in sorted(exts.keys()):
        arr = np.array(exts[e])
        print(f"  {e:8s}  n={len(arr):3d}  "
              f"mean={arr.mean():.4f}  min={arr.min():.4f}  max={arr.max():.4f}  "
              f"std={arr.std():.4f}")

    # ── Retraining recommendation ─────────────────────────────────────────
    print(f"\n{'='*70}")
    print("RETRAINING RECOMMENDATIONS")
    print(f"{'='*70}")
    print("""
  To fix the model, retrain with REAL files:

  1. Create a benign validation directory:
       mkdir -p samples/benign
       # Copy normal files: .html, .css, .js, .jpg, .png, .pdf,
       # .zip, .py, .cpp, .txt, .md, .json, .xml, .csv, etc.
       # Aim for 200+ files, diverse file types

  2. If you have malware samples:
       mkdir -p samples/malware
       # Copy known-malicious files (from MalwareBazaar, etc.)

  3. Generate the dataset:
       python generate_dataset.py --benign-dir samples/benign \\
                                   --malware-dir samples/malware \\
                                   --output dataset_real.csv

  4. Train the model:
       python train_model.py --dataset dataset_real.csv \\
                              --output ../data/anomaly_model.onnx

  5. Verify:
       python diagnose_model.py --model ../data/anomaly_model.onnx \\
                                 --benign-dir samples/benign
       # Now p(malicious) should be < 0.30 for most benign files
""")


def main():
    parser = argparse.ArgumentParser(description="Diagnose ONNX anomaly model")
    parser.add_argument("--model", required=True, help="Path to anomaly_model.onnx")
    parser.add_argument("--benign-dir", required=True,
                        help="Directory of known-benign files to test against")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress per-file output")
    args = parser.parse_args()

    if not os.path.isfile(args.model):
        print(f"Error: model not found: {args.model}")
        sys.exit(1)
    if not os.path.isdir(args.benign_dir):
        print(f"Error: directory not found: {args.benign_dir}")
        sys.exit(1)

    diagnose(args.model, args.benign_dir, verbose=not args.quiet)


if __name__ == "__main__":
    main()
