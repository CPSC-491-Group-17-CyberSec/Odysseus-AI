#!/usr/bin/env python3
"""
test_feature_extractor.py  –  Validate the Python feature extractor.

Creates temporary test files (text, binary, fake PE) and verifies
that feature extraction produces sensible values.

Usage:
    python test_feature_extractor.py
"""

import os
import struct
import tempfile
from generate_dataset import extract_features, FEATURE_NAMES, NUM_FEATURES


def create_text_file(path):
    """Normal text file."""
    with open(path, "w") as f:
        f.write("Hello world! " * 100)
        f.write("\nThis is a normal text file.\n")
        f.write("It contains mostly printable ASCII characters.\n" * 20)


def create_binary_file(path):
    """Random-looking binary file."""
    import random
    random.seed(123)
    with open(path, "wb") as f:
        f.write(bytes(random.randint(0, 255) for _ in range(4096)))


def create_fake_pe(path, suspicious=False):
    """Create a minimal PE-like file for testing PE parsing."""
    buf = bytearray(4096)

    # MZ header
    buf[0:2] = b"MZ"
    # e_lfanew at 0x3C -> point to offset 0x80
    struct.pack_into("<I", buf, 0x3C, 0x80)

    # PE signature at 0x80
    buf[0x80:0x84] = b"PE\x00\x00"

    # COFF header at 0x84 (20 bytes)
    struct.pack_into("<H", buf, 0x84, 0x14C)   # machine: i386
    struct.pack_into("<H", buf, 0x86, 2)        # numSections
    ts = 1700000000 if not suspicious else 100000  # suspicious = very old timestamp
    struct.pack_into("<I", buf, 0x88, ts)        # timeDateStamp
    struct.pack_into("<H", buf, 0x94, 0xE0)      # sizeOfOptionalHeader (224 for PE32)
    struct.pack_into("<H", buf, 0x96, 0x0102)    # characteristics

    # Optional header at 0x98 (PE32, magic = 0x10B)
    opt_start = 0x98
    struct.pack_into("<H", buf, opt_start, 0x10B)  # magic
    struct.pack_into("<I", buf, opt_start + 16, 0x1000)  # AddressOfEntryPoint

    struct.pack_into("<I", buf, opt_start + 92, 16)  # NumberOfRvaAndSizes

    # Section table starts after optional header
    sec_start = opt_start + 0xE0  # = 0x98 + 0xE0 = 0x178

    # Section 1: .text
    name = b".text\x00\x00\x00" if not suspicious else b"UPX0\x00\x00\x00\x00"
    buf[sec_start:sec_start+8] = name
    struct.pack_into("<I", buf, sec_start + 8, 0x1000)    # VirtualSize
    struct.pack_into("<I", buf, sec_start + 12, 0x1000)   # VirtualAddress
    struct.pack_into("<I", buf, sec_start + 16, 0x200)    # SizeOfRawData
    struct.pack_into("<I", buf, sec_start + 20, 0x200)    # PointerToRawData
    struct.pack_into("<I", buf, sec_start + 36, 0x60000020)  # CODE | EXECUTE | READ

    # Section 2: .rdata
    sec2 = sec_start + 40
    buf[sec2:sec2+8] = b".rdata\x00\x00" if not suspicious else b".ndata\x00\x00"
    struct.pack_into("<I", buf, sec2 + 8, 0x500)
    struct.pack_into("<I", buf, sec2 + 12, 0x2000)
    struct.pack_into("<I", buf, sec2 + 16, 0x200)
    struct.pack_into("<I", buf, sec2 + 20, 0x400)
    struct.pack_into("<I", buf, sec2 + 36, 0x40000040)  # INITIALIZED_DATA | READ

    # Write some data in sections
    for i in range(0x200, 0x400):
        buf[i] = i % 256
    for i in range(0x400, 0x600):
        buf[i] = (i * 7) % 256

    # If suspicious, add suspicious strings
    if suspicious:
        suspicious_strs = b"cmd.exe\x00powershell.exe\x00CreateRemoteThread\x00http://evil.com/payload\x00HKEY_LOCAL_MACHINE\\SOFTWARE\\Run\x00"
        buf[0x600:0x600+len(suspicious_strs)] = suspicious_strs

    with open(path, "wb") as f:
        f.write(buf)


def print_features(feats, label):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    for i, (name, val) in enumerate(zip(FEATURE_NAMES, feats)):
        flag = ""
        if "suspicious" in name.lower() and val > 0:
            flag = " <-- FLAGGED"
        elif name == "isPE" and val > 0:
            flag = " <-- PE DETECTED"
        elif "anomaly" in name.lower() and val > 0:
            flag = " <-- ANOMALY"
        print(f"  [{i:2d}] {name:30s} = {val:.4f}{flag}")


def main():
    tmpdir = tempfile.mkdtemp()
    print(f"Test directory: {tmpdir}")

    # Test 1: Text file
    txt_path = os.path.join(tmpdir, "normal.txt")
    create_text_file(txt_path)
    feats = extract_features(txt_path)
    assert len(feats) == NUM_FEATURES, f"Expected {NUM_FEATURES} features, got {len(feats)}"
    assert feats[2] == 0.0, "Text file should not be flagged as executable"
    assert feats[16] == 0.0, "Text file should not be detected as PE"
    assert feats[6] > 0.5, "Text file should have high printable ratio"
    print_features(feats, "NORMAL TEXT FILE")
    print("  PASS: Text file features look correct")

    # Test 2: Binary file
    bin_path = os.path.join(tmpdir, "random.bin")
    create_binary_file(bin_path)
    feats = extract_features(bin_path)
    assert len(feats) == NUM_FEATURES
    assert feats[1] > 6.0, "Random binary should have high entropy"
    assert feats[12] > 0.8, "Random binary should have many unique byte values"
    print_features(feats, "RANDOM BINARY FILE")
    print("  PASS: Binary file features look correct")

    # Test 3: Clean PE
    pe_path = os.path.join(tmpdir, "clean.exe")
    create_fake_pe(pe_path, suspicious=False)
    feats = extract_features(pe_path)
    assert len(feats) == NUM_FEATURES
    assert feats[2] == 1.0, "Should be flagged as executable"
    assert feats[16] == 1.0, "Should be detected as PE"
    assert feats[25] == 0.0, "Clean PE should have no section name anomaly"
    assert feats[26] == 0.0, "Clean PE should have no timestamp anomaly"
    print_features(feats, "CLEAN PE EXECUTABLE")
    print("  PASS: Clean PE features look correct")

    # Test 4: Suspicious PE
    susp_path = os.path.join(tmpdir, "suspect.exe")
    create_fake_pe(susp_path, suspicious=True)
    feats = extract_features(susp_path)
    assert len(feats) == NUM_FEATURES
    assert feats[16] == 1.0, "Should be detected as PE"
    assert feats[25] == 1.0, "Should have section name anomaly (UPX0, .ndata)"
    assert feats[26] == 1.0, "Should have timestamp anomaly (very old)"
    assert feats[32] > 0.0, "Should have suspicious strings"
    assert feats[33] > 0.0, "Should have URL strings"
    assert feats[35] > 0.0, "Should have registry path strings"
    print_features(feats, "SUSPICIOUS PE EXECUTABLE")
    print("  PASS: Suspicious PE features look correct")

    # Test 5: Empty / nonexistent file
    feats = extract_features("/nonexistent/file.txt")
    assert feats == [], "Nonexistent file should return empty features"
    print("\n  PASS: Nonexistent file returns empty")

    print(f"\n{'='*60}")
    print("  ALL TESTS PASSED!")
    print(f"{'='*60}")

    # Cleanup
    for f in os.listdir(tmpdir):
        os.remove(os.path.join(tmpdir, f))
    os.rmdir(tmpdir)


if __name__ == "__main__":
    main()
