#!/usr/bin/env python3
"""
generate_synthetic_dataset.py  –  Create a synthetic training dataset.

Generates realistic-looking feature vectors for benign and malicious files
when real malware samples aren't available.  This allows you to train and
test the full pipeline end-to-end.

For production use, replace this with real samples via generate_dataset.py.

Usage:
    python generate_synthetic_dataset.py --output dataset.csv --samples 2000
"""

import argparse
import csv
import random
import math

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

def clamp(v, lo=0.0, hi=1.0):
    return max(lo, min(hi, v))

def gen_benign_exe():
    """Simulate a normal executable file."""
    f = [0.0] * 38
    f[0] = random.gauss(5.5, 0.8)        # ~300KB typical exe
    f[1] = random.gauss(5.5, 0.8)        # moderate entropy
    f[2] = 1.0                             # isExecutable
    f[3] = 0.0
    f[4] = random.choice([0.0, 1.0])      # maybe DLL
    f[5] = clamp(random.gauss(0.15, 0.05))  # some nulls
    f[6] = clamp(random.gauss(0.3, 0.1))    # moderate printable
    f[7] = clamp(random.gauss(0.3, 0.1))    # moderate high bytes
    f[8] = clamp(random.gauss(0.5, 0.1))    # byte mean ~128
    f[9] = clamp(random.gauss(0.55, 0.1))   # moderate variance
    f[10] = clamp(random.gauss(0.02, 0.01)) # few control chars
    f[11] = clamp(random.gauss(0.05, 0.02)) # some whitespace
    f[12] = clamp(random.gauss(0.95, 0.03)) # most byte values present
    f[13] = clamp(random.gauss(0.01, 0.005)) # short null runs
    f[14] = clamp(random.gauss(0.7, 0.15), 0, 1)
    f[15] = clamp(random.gauss(0.65, 0.15), 0, 1)
    # PE features
    f[16] = 1.0                             # isPE
    f[17] = clamp(random.gauss(0.3, 0.1))   # 4-5 sections / 16
    f[18] = clamp(random.gauss(0.7, 0.1))   # moderate section entropy
    f[19] = clamp(random.gauss(0.3, 0.1))   # code section ratio
    f[20] = 1.0                             # EP in code
    f[21] = random.choice([0.0, 1.0])       # debug info
    f[22] = clamp(random.gauss(0.3, 0.1))   # moderate imports
    f[23] = random.choice([0.0, 1.0])       # exports
    f[24] = clamp(random.gauss(0.15, 0.05)) # resource ratio
    f[25] = 0.0                             # no section name anomaly
    f[26] = 0.0                             # no timestamp anomaly
    f[27] = clamp(random.gauss(0.1, 0.05))  # low virt/raw ratio
    # Strings
    f[28] = random.gauss(2.5, 0.5)          # moderate string count
    f[29] = clamp(random.gauss(0.15, 0.05)) # string density
    f[30] = clamp(random.gauss(0.1, 0.03))  # avg length
    f[31] = clamp(random.gauss(0.1, 0.05))  # max length
    f[32] = clamp(random.gauss(0.05, 0.03)) # few suspicious strings (normal APIs)
    f[33] = 0.0                             # no URLs
    f[34] = 0.0                             # no IPs
    f[35] = 0.0                             # no registry
    f[36] = clamp(random.gauss(0.02, 0.01)) # rare base64
    f[37] = 0.0
    return f

def gen_benign_doc():
    """Simulate a normal document/text file."""
    f = [0.0] * 38
    f[0] = random.gauss(4.0, 1.0)          # ~10KB
    f[1] = random.gauss(4.5, 0.5)          # lower entropy (text)
    f[2] = 0.0
    f[3] = 0.0
    f[4] = 0.0
    f[5] = clamp(random.gauss(0.02, 0.01))
    f[6] = clamp(random.gauss(0.8, 0.1))   # mostly printable
    f[7] = clamp(random.gauss(0.02, 0.01))
    f[8] = clamp(random.gauss(0.35, 0.05))
    f[9] = clamp(random.gauss(0.2, 0.05))
    f[10] = clamp(random.gauss(0.01, 0.005))
    f[11] = clamp(random.gauss(0.2, 0.05))  # lots of whitespace
    f[12] = clamp(random.gauss(0.3, 0.1))   # limited byte values
    f[13] = clamp(random.gauss(0.001, 0.001))
    f[14] = clamp(random.gauss(0.55, 0.1), 0, 1)
    f[15] = clamp(random.gauss(0.55, 0.1), 0, 1)
    # No PE
    f[16] = 0.0
    # Strings
    f[28] = random.gauss(2.0, 0.5)
    f[29] = clamp(random.gauss(0.7, 0.1))
    f[30] = clamp(random.gauss(0.08, 0.02))
    f[31] = clamp(random.gauss(0.05, 0.02))
    f[32] = 0.0
    f[33] = clamp(random.gauss(0.05, 0.03))  # maybe some URLs
    f[34] = 0.0
    f[35] = 0.0
    f[36] = 0.0
    f[37] = 0.0
    return f

def gen_malware_packed():
    """Simulate a packed/obfuscated malware executable."""
    f = [0.0] * 38
    f[0] = random.gauss(5.0, 0.5)          # moderate size
    f[1] = random.gauss(7.5, 0.3)          # HIGH entropy (packed)
    f[2] = 1.0                             # executable
    f[3] = 0.0
    f[4] = random.choice([0.0, 1.0])
    f[5] = clamp(random.gauss(0.05, 0.02))
    f[6] = clamp(random.gauss(0.1, 0.05))  # low printable (packed)
    f[7] = clamp(random.gauss(0.5, 0.1))   # lots of high bytes
    f[8] = clamp(random.gauss(0.5, 0.05))
    f[9] = clamp(random.gauss(0.6, 0.05))
    f[10] = clamp(random.gauss(0.03, 0.02))
    f[11] = clamp(random.gauss(0.01, 0.005))
    f[12] = clamp(random.gauss(0.99, 0.01))  # nearly all byte values
    f[13] = clamp(random.gauss(0.001, 0.001))
    f[14] = clamp(random.gauss(0.9, 0.05), 0, 1)  # high entropy throughout
    f[15] = clamp(random.gauss(0.9, 0.05), 0, 1)
    # PE
    f[16] = 1.0
    f[17] = clamp(random.gauss(0.2, 0.1))   # fewer sections
    f[18] = clamp(random.gauss(0.95, 0.03))  # very high section entropy
    f[19] = clamp(random.gauss(0.1, 0.05))   # small code section
    f[20] = random.choice([0.0, 1.0])
    f[21] = 0.0                              # no debug info
    f[22] = clamp(random.gauss(0.05, 0.03))  # few imports (packed)
    f[23] = 0.0
    f[24] = clamp(random.gauss(0.02, 0.01))
    f[25] = 1.0                              # section name anomaly (UPX etc)
    f[26] = random.choice([0.0, 1.0])        # maybe bad timestamp
    f[27] = clamp(random.gauss(0.8, 0.1))    # HIGH virt/raw ratio (unpacking)
    # Strings
    f[28] = random.gauss(1.0, 0.3)           # few strings (packed)
    f[29] = clamp(random.gauss(0.03, 0.02))
    f[30] = clamp(random.gauss(0.05, 0.02))
    f[31] = clamp(random.gauss(0.04, 0.02))
    f[32] = clamp(random.gauss(0.1, 0.05))
    f[33] = 0.0
    f[34] = 0.0
    f[35] = 0.0
    f[36] = clamp(random.gauss(0.1, 0.05))   # base64 encoded payloads
    f[37] = 0.0
    return f

def gen_malware_trojan():
    """Simulate a trojan with suspicious API calls and network indicators."""
    f = [0.0] * 38
    f[0] = random.gauss(5.2, 0.6)
    f[1] = random.gauss(6.0, 0.5)          # medium-high entropy
    f[2] = 1.0
    f[3] = 0.0
    f[4] = random.choice([0.0, 1.0])
    f[5] = clamp(random.gauss(0.1, 0.03))
    f[6] = clamp(random.gauss(0.25, 0.08))
    f[7] = clamp(random.gauss(0.35, 0.08))
    f[8] = clamp(random.gauss(0.48, 0.05))
    f[9] = clamp(random.gauss(0.55, 0.05))
    f[10] = clamp(random.gauss(0.02, 0.01))
    f[11] = clamp(random.gauss(0.03, 0.01))
    f[12] = clamp(random.gauss(0.9, 0.05))
    f[13] = clamp(random.gauss(0.005, 0.003))
    f[14] = clamp(random.gauss(0.75, 0.1), 0, 1)
    f[15] = clamp(random.gauss(0.7, 0.1), 0, 1)
    # PE
    f[16] = 1.0
    f[17] = clamp(random.gauss(0.35, 0.1))
    f[18] = clamp(random.gauss(0.75, 0.1))
    f[19] = clamp(random.gauss(0.25, 0.08))
    f[20] = 1.0
    f[21] = 0.0
    f[22] = clamp(random.gauss(0.5, 0.15))   # MANY imports (API abuse)
    f[23] = 0.0
    f[24] = clamp(random.gauss(0.1, 0.05))
    f[25] = random.choice([0.0, 1.0])
    f[26] = random.choice([0.0, 1.0])
    f[27] = clamp(random.gauss(0.15, 0.08))
    # Strings – lots of suspicious content
    f[28] = random.gauss(2.3, 0.4)
    f[29] = clamp(random.gauss(0.12, 0.04))
    f[30] = clamp(random.gauss(0.12, 0.03))
    f[31] = clamp(random.gauss(0.15, 0.05))
    f[32] = clamp(random.gauss(0.6, 0.15))   # HIGH suspicious strings
    f[33] = clamp(random.gauss(0.3, 0.15))    # URLs
    f[34] = clamp(random.gauss(0.2, 0.1))     # IP addresses
    f[35] = clamp(random.gauss(0.4, 0.15))    # registry paths
    f[36] = clamp(random.gauss(0.15, 0.08))
    f[37] = 0.0
    return f

def gen_malware_script():
    """Simulate a malicious script (PowerShell dropper, etc.)."""
    f = [0.0] * 38
    f[0] = random.gauss(3.5, 0.8)          # small file
    f[1] = random.gauss(5.0, 0.5)
    f[2] = 0.0
    f[3] = 1.0                             # isScript
    f[4] = 0.0
    f[5] = clamp(random.gauss(0.01, 0.005))
    f[6] = clamp(random.gauss(0.85, 0.05)) # mostly text
    f[7] = clamp(random.gauss(0.01, 0.005))
    f[8] = clamp(random.gauss(0.35, 0.05))
    f[9] = clamp(random.gauss(0.2, 0.05))
    f[10] = clamp(random.gauss(0.01, 0.005))
    f[11] = clamp(random.gauss(0.15, 0.05))
    f[12] = clamp(random.gauss(0.35, 0.1))
    f[13] = clamp(random.gauss(0.001, 0.001))
    f[14] = clamp(random.gauss(0.6, 0.1), 0, 1)
    f[15] = clamp(random.gauss(0.65, 0.1), 0, 1)
    # No PE
    f[16] = 0.0
    # Strings
    f[28] = random.gauss(2.0, 0.4)
    f[29] = clamp(random.gauss(0.6, 0.1))
    f[30] = clamp(random.gauss(0.15, 0.05))
    f[31] = clamp(random.gauss(0.3, 0.1))
    f[32] = clamp(random.gauss(0.4, 0.15))   # suspicious keywords
    f[33] = clamp(random.gauss(0.3, 0.15))    # download URLs
    f[34] = clamp(random.gauss(0.15, 0.1))
    f[35] = clamp(random.gauss(0.3, 0.15))    # registry
    f[36] = clamp(random.gauss(0.5, 0.2))     # base64 encoded payload
    f[37] = 0.0
    return f


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="dataset.csv")
    parser.add_argument("--samples", type=int, default=2000,
                        help="Total samples (split evenly)")
    args = parser.parse_args()

    random.seed(42)
    n_per_class = args.samples // 2
    rows = []

    generators_benign = [gen_benign_exe, gen_benign_doc]
    generators_malware = [gen_malware_packed, gen_malware_trojan, gen_malware_script]

    for _ in range(n_per_class):
        gen = random.choice(generators_benign)
        rows.append([0] + gen())

    for _ in range(n_per_class):
        gen = random.choice(generators_malware)
        rows.append([1] + gen())

    random.shuffle(rows)

    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["label"] + FEATURE_NAMES)
        writer.writerows(rows)

    print(f"Synthetic dataset: {len(rows)} samples -> {args.output}")
    print(f"  Benign:    {n_per_class}")
    print(f"  Malicious: {n_per_class}")


if __name__ == "__main__":
    main()
