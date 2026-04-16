#!/usr/bin/env python3
"""
generate_dataset_v3.py  –  Phase 4 dataset generation.

Supports the three-class directory structure:

    training_data/
        benign/        → label 0
        suspicious/    → label 1
        malware/       → label 1  (future real samples)

Also mixes in synthetic malware vectors (from generate_synthetic_dataset.py)
since we have no real malware samples yet.

Output CSV columns:
    label, file_type, source_class, <38 feature columns>

    source_class values: benign | suspicious | malware | synthetic_malware
    (source_class is metadata only — the model sees label 0 vs 1)

Usage:
    python generate_dataset_v3.py \\
        --benign-dir      ../training_data/benign \\
        --suspicious-dir  ../training_data/suspicious \\
        --malware-dir     ../training_data/malware \\
        --synthetic-malware 800 \\
        --synthetic-benign  400 \\
        --output          dataset_v3.csv
"""

import argparse
import csv
import os
import random
import sys
from pathlib import Path

# Reuse feature extraction from the existing pipeline
SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))
from generate_dataset import (
    extract_features, categorize_file, FEATURE_NAMES, NUM_FEATURES,
)
from generate_synthetic_dataset import (
    gen_benign_exe, gen_benign_doc,
    gen_malware_packed, gen_malware_trojan, gen_malware_script,
)


def walk_directory(directory, label, source_class, include_path=False):
    """Walk a directory tree and extract features for every file."""
    rows = []
    if not os.path.isdir(directory):
        print(f"  [SKIP] {directory} does not exist")
        return rows

    count = 0
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if not d.startswith(".")
                   and d.lower() not in ("node_modules", "__pycache__", ".git")]
        for fname in files:
            if fname.startswith("."):
                continue
            fpath = os.path.join(root, fname)
            feats = extract_features(fpath)
            if feats:
                file_type = categorize_file(fpath)
                row = [label, file_type, source_class] + feats
                if include_path:
                    row.append(fpath)
                rows.append(row)
                count += 1
                if count % 50 == 0:
                    print(f"    [{source_class}] Processed {count} files...")

    print(f"  {source_class}: extracted {count} feature vectors from {directory}")
    return rows


def generate_synthetic(n_benign, n_malware):
    """Generate synthetic feature vectors to supplement real data."""
    rows = []
    random.seed(42)

    benign_gens = [gen_benign_exe, gen_benign_doc]
    malware_gens = [gen_malware_packed, gen_malware_trojan, gen_malware_script]

    # Synthetic benign
    type_map_benign = {gen_benign_exe: "pe_binary", gen_benign_doc: "text_data"}
    for _ in range(n_benign):
        gen = random.choice(benign_gens)
        feats = gen()
        file_type = type_map_benign[gen]
        rows.append([0, file_type, "synthetic_benign"] + feats)

    # Synthetic malware
    type_map_malware = {
        gen_malware_packed: "pe_binary",
        gen_malware_trojan: "pe_binary",
        gen_malware_script: "script",
    }
    for _ in range(n_malware):
        gen = random.choice(malware_gens)
        feats = gen()
        file_type = type_map_malware[gen]
        rows.append([1, file_type, "synthetic_malware"] + feats)

    print(f"  synthetic_benign:  generated {n_benign} vectors")
    print(f"  synthetic_malware: generated {n_malware} vectors")
    return rows


def main():
    parser = argparse.ArgumentParser(
        description="Phase 4 dataset generation with 3-class support",
    )
    parser.add_argument("--benign-dir", default="../training_data/benign",
                        help="Directory of benign files (label=0)")
    parser.add_argument("--suspicious-dir", default="../training_data/suspicious",
                        help="Directory of suspicious files (label=1)")
    parser.add_argument("--malware-dir", default="../training_data/malware",
                        help="Directory of real malware files (label=1, future)")
    parser.add_argument("--synthetic-malware", type=int, default=800,
                        help="Number of synthetic malware vectors to generate")
    parser.add_argument("--synthetic-benign", type=int, default=400,
                        help="Number of synthetic benign vectors to generate")
    parser.add_argument("--output", default="dataset_v3.csv",
                        help="Output CSV path")
    parser.add_argument("--include-path", action="store_true",
                        help="Include source file path in CSV (debugging)")
    args = parser.parse_args()

    print("=" * 65)
    print("Odysseus-AI Dataset Generation (Phase 4 / v3)")
    print("=" * 65)

    rows = []

    # ── Real files ────────────────────────────────────────────────────
    print("\nExtracting features from real files:")
    rows += walk_directory(args.benign_dir, 0, "benign", args.include_path)
    rows += walk_directory(args.suspicious_dir, 1, "suspicious", args.include_path)
    rows += walk_directory(args.malware_dir, 1, "malware", args.include_path)

    # ── Synthetic data ────────────────────────────────────────────────
    print("\nGenerating synthetic vectors:")
    synth = generate_synthetic(args.synthetic_benign, args.synthetic_malware)
    if args.include_path:
        synth = [r + ["<synthetic>"] for r in synth]
    rows += synth

    if not rows:
        print("\nERROR: No data generated. Check input directories.")
        sys.exit(1)

    # ── Shuffle and write ─────────────────────────────────────────────
    random.seed(42)
    random.shuffle(rows)

    header = ["label", "file_type", "source_class"] + FEATURE_NAMES
    if args.include_path:
        header.append("file_path")

    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)

    # ── Summary ───────────────────────────────────────────────────────
    n_benign = sum(1 for r in rows if r[0] == 0)
    n_malicious = sum(1 for r in rows if r[0] == 1)

    source_counts = {}
    type_counts = {}
    for r in rows:
        src = r[2]
        ft = r[1]
        source_counts[src] = source_counts.get(src, 0) + 1
        type_counts[ft] = type_counts.get(ft, 0) + 1

    print(f"\n{'=' * 65}")
    print(f"Dataset Summary")
    print(f"{'=' * 65}")
    print(f"  Output:     {args.output}")
    print(f"  Total:      {len(rows)} samples")
    print(f"  Benign (0): {n_benign}")
    print(f"  Flagged (1):{n_malicious}")
    print(f"\n  By source:")
    for src, count in sorted(source_counts.items()):
        print(f"    {src:22s}: {count:5d}")
    print(f"\n  By file type:")
    for ft, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"    {ft:15s}: {count:5d}")
    print(f"{'=' * 65}")


if __name__ == "__main__":
    main()
