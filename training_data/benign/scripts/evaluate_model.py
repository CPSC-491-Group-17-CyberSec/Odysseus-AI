#!/usr/bin/env python3
"""
evaluate_model.py  –  Comprehensive model evaluation with per-type analysis.

Loads a trained ONNX model and a test dataset, then produces:
    1. Overall metrics (accuracy, ROC-AUC, precision, recall, F1)
    2. Per-file-type score distributions (benign vs. malicious)
    3. Per-file-type FPR/TPR at multiple thresholds
    4. Threshold recommendations (optimized for low FPR)
    5. Score histograms (text-based) for visual sanity checking
    6. Calibration assessment (are probabilities well-calibrated?)
    7. Feature importance from the dataset (correlation-based)

Usage:
    python evaluate_model.py --model ../data/anomaly_model.onnx --dataset dataset_v2.csv
    python evaluate_model.py --model ../data/anomaly_model.onnx --benign-dir training_data/benign
    python evaluate_model.py --model ../data/anomaly_model.onnx --dataset dataset_v2.csv --html report.html

Requirements:
    pip install numpy pandas onnxruntime scikit-learn
"""

import argparse
import json
import math
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

# ============================================================================
# Feature extraction (reuse from generate_dataset.py)
# ============================================================================

# Import feature extraction if available in the same directory
SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))
try:
    from generate_dataset import extract_features, FEATURE_NAMES, NUM_FEATURES
except ImportError:
    print("WARNING: Could not import from generate_dataset.py")
    print("Place evaluate_model.py in the same directory as generate_dataset.py")
    FEATURE_NAMES = None
    NUM_FEATURES = 38


# ============================================================================
# File-type categorization (mirrors collect_benign_dataset.py)
# ============================================================================

EXT_CATEGORIES = {
    "pe_binary": {"exe", "dll", "sys", "drv", "ocx", "com", "scr", "pif"},
    "script": {"py", "sh", "bash", "ps1", "bat", "cmd", "vbs", "js", "wsh",
               "wsf", "pl", "rb", "php", "lua", "tcl", "zsh"},
    "web_content": {"html", "htm", "xhtml", "css", "svg", "xml", "xsl",
                    "json", "jsx", "tsx", "vue"},
    "text_data": {"txt", "md", "rst", "csv", "tsv", "log", "cfg", "conf",
                  "ini", "yaml", "yml", "toml", "c", "cpp", "h", "hpp",
                  "java", "cs", "go", "rs", "swift", "kt", "ts", "r"},
    "archive": {"zip", "gz", "tar", "bz2", "xz", "7z", "rar", "zst"},
    "installer": {"msi", "deb", "rpm", "pkg", "dmg", "appimage"},
    "media_binary": {"png", "jpg", "jpeg", "gif", "bmp", "ico", "webp",
                     "mp3", "wav", "flac", "ogg", "mp4", "mkv", "avi",
                     "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
                     "ttf", "otf", "woff", "woff2"},
}

EXT_TO_CAT = {}
for cat, exts in EXT_CATEGORIES.items():
    for ext in exts:
        EXT_TO_CAT[ext] = cat


def infer_file_type_from_features(row):
    """Infer file type from feature values when no file_type column exists."""
    if row.get("isPE", 0) == 1.0:
        return "pe_binary"
    if row.get("isScript", 0) == 1.0:
        return "script"
    if row.get("isExecutable", 0) == 1.0:
        return "pe_binary"
    if row.get("isDLL", 0) == 1.0:
        return "pe_binary"
    if row.get("printableAsciiRatio", 0) > 0.7 and row.get("highByteRatio", 0) < 0.05:
        if row.get("urlCount", 0) > 0.05:
            return "web_content"
        return "text_data"
    if row.get("shannonEntropy", 0) > 7.0 and row.get("printableAsciiRatio", 0) < 0.3:
        return "archive"
    if row.get("highByteRatio", 0) > 0.3:
        return "media_binary"
    return "other"


# ============================================================================
# ONNX inference
# ============================================================================

def load_onnx_model(model_path):
    """Load ONNX model and return inference session."""
    import onnxruntime as ort
    sess = ort.InferenceSession(model_path)
    input_name = sess.get_inputs()[0].name
    print(f"  Model loaded: {model_path}")
    print(f"    Inputs:  {[i.name for i in sess.get_inputs()]}")
    print(f"    Outputs: {[o.name for o in sess.get_outputs()]}")
    return sess, input_name


def run_inference(sess, input_name, X):
    """Run ONNX inference, return p(malicious) scores."""
    results = sess.run(None, {input_name: X.astype(np.float32)})

    if len(results) >= 2:
        probs = np.array(results[1])
        if probs.ndim == 2 and probs.shape[1] >= 2:
            return probs[:, 1]
        return probs.flatten()
    return np.array(results[0]).flatten()


# ============================================================================
# Evaluation metrics
# ============================================================================

def compute_metrics_at_threshold(y_true, scores, threshold):
    """Compute metrics at a given threshold."""
    y_pred = (scores > threshold).astype(int)
    n = len(y_true)
    tp = ((y_pred == 1) & (y_true == 1)).sum()
    fp = ((y_pred == 1) & (y_true == 0)).sum()
    tn = ((y_pred == 0) & (y_true == 0)).sum()
    fn = ((y_pred == 0) & (y_true == 1)).sum()
    fpr = fp / max(fp + tn, 1)
    tpr = tp / max(tp + fn, 1)
    precision = tp / max(tp + fp, 1)
    f1 = 2 * precision * tpr / max(precision + tpr, 1e-10)
    return {"threshold": threshold, "TP": int(tp), "FP": int(fp),
            "TN": int(tn), "FN": int(fn), "FPR": fpr, "TPR": tpr,
            "precision": precision, "F1": f1}


def text_histogram(values, bins=20, width=50, label=""):
    """Print a text-based histogram."""
    if len(values) == 0:
        print(f"    {label}: (no data)")
        return

    hist, edges = np.histogram(values, bins=bins, range=(0.0, 1.0))
    max_count = max(hist) if max(hist) > 0 else 1

    print(f"    {label} (n={len(values)}, mean={values.mean():.3f}, "
          f"std={values.std():.3f})")
    for i in range(len(hist)):
        bar_len = int(hist[i] / max_count * width)
        bar = "#" * bar_len
        print(f"      [{edges[i]:.2f}-{edges[i+1]:.2f}] {hist[i]:5d} {bar}")


# ============================================================================
# Main evaluation
# ============================================================================

def evaluate_from_dataset(sess, input_name, df):
    """Run full evaluation on a dataset DataFrame."""
    feature_cols = [c for c in df.columns if c not in ("label", "file_type", "file_path")]
    X = df[feature_cols].values.astype(np.float32)
    y = df["label"].values

    if "file_type" in df.columns:
        file_types = df["file_type"].values
    else:
        file_types = np.array([infer_file_type_from_features(row)
                               for _, row in df[feature_cols].iterrows()])

    # Run inference
    print(f"\n  Running inference on {len(X)} samples...")
    scores = run_inference(sess, input_name, X)

    # ── Overall metrics ──────────────────────────────────────────────
    from sklearn.metrics import roc_auc_score, accuracy_score
    print(f"\n{'=' * 65}")
    print(f"OVERALL METRICS")
    print(f"{'=' * 65}")

    y_pred_50 = (scores > 0.5).astype(int)
    print(f"  Accuracy (t=0.5): {accuracy_score(y, y_pred_50):.4f}")
    try:
        auc = roc_auc_score(y, scores)
        print(f"  ROC-AUC:          {auc:.4f}")
    except ValueError:
        auc = None
        print(f"  ROC-AUC:          N/A (single class)")

    # ── Score distributions ──────────────────────────────────────────
    print(f"\n{'=' * 65}")
    print(f"SCORE DISTRIBUTIONS")
    print(f"{'=' * 65}")

    benign_scores = scores[y == 0]
    mal_scores = scores[y == 1]

    print(f"\n  Benign files (n={len(benign_scores)}):")
    if len(benign_scores) > 0:
        print(f"    mean={benign_scores.mean():.4f}  std={benign_scores.std():.4f}  "
              f"min={benign_scores.min():.4f}  max={benign_scores.max():.4f}  "
              f"median={np.median(benign_scores):.4f}")
        text_histogram(benign_scores, label="Benign p(malicious)")

    print(f"\n  Malicious files (n={len(mal_scores)}):")
    if len(mal_scores) > 0:
        print(f"    mean={mal_scores.mean():.4f}  std={mal_scores.std():.4f}  "
              f"min={mal_scores.min():.4f}  max={mal_scores.max():.4f}  "
              f"median={np.median(mal_scores):.4f}")
        text_histogram(mal_scores, label="Malicious p(malicious)")

    # ── Per-type analysis ────────────────────────────────────────────
    print(f"\n{'=' * 65}")
    print(f"PER-TYPE ANALYSIS")
    print(f"{'=' * 65}")

    per_type_data = {}
    for ft in sorted(set(file_types)):
        mask = file_types == ft
        ft_y = y[mask]
        ft_scores = scores[mask]
        ft_benign = ft_scores[ft_y == 0]
        ft_mal = ft_scores[ft_y == 1]

        print(f"\n  ── {ft} (n={mask.sum()}, benign={len(ft_benign)}, mal={len(ft_mal)}) ──")

        if len(ft_benign) > 0:
            fpr_50 = (ft_benign > 0.5).mean()
            print(f"    Benign: mean={ft_benign.mean():.4f}  max={ft_benign.max():.4f}  "
                  f"FPR@0.5={fpr_50:.4f}")
            if fpr_50 > 0.01:
                print(f"    *** HIGH FPR: {fpr_50*100:.1f}% of benign {ft} files would be flagged! ***")

        if len(ft_mal) > 0:
            tpr_50 = (ft_mal > 0.5).mean()
            print(f"    Malware: mean={ft_mal.mean():.4f}  min={ft_mal.min():.4f}  "
                  f"TPR@0.5={tpr_50:.4f}")

        per_type_data[ft] = {
            "n": int(mask.sum()),
            "n_benign": int(len(ft_benign)),
            "n_malicious": int(len(ft_mal)),
            "benign_mean": float(ft_benign.mean()) if len(ft_benign) > 0 else None,
            "benign_max": float(ft_benign.max()) if len(ft_benign) > 0 else None,
            "malware_mean": float(ft_mal.mean()) if len(ft_mal) > 0 else None,
            "malware_min": float(ft_mal.min()) if len(ft_mal) > 0 else None,
        }

    # ── Threshold sweep ──────────────────────────────────────────────
    print(f"\n{'=' * 65}")
    print(f"THRESHOLD SWEEP")
    print(f"{'=' * 65}")
    print(f"  {'Threshold':>10s} {'FP':>5s} {'FN':>5s} {'FPR':>7s} {'TPR':>7s} "
          f"{'Precision':>10s} {'F1':>7s}")
    print(f"  {'-' * 55}")

    best_f1 = 0
    best_thresh = 0.5
    for t in np.arange(0.1, 0.95, 0.05):
        m = compute_metrics_at_threshold(y, scores, t)
        print(f"  {t:10.2f} {m['FP']:5d} {m['FN']:5d} {m['FPR']:7.4f} {m['TPR']:7.4f} "
              f"{m['precision']:10.4f} {m['F1']:7.4f}")
        if m['F1'] > best_f1:
            best_f1 = m['F1']
            best_thresh = t

    print(f"\n  Best F1={best_f1:.4f} at threshold={best_thresh:.2f}")

    # ── Per-type threshold recommendations ───────────────────────────
    print(f"\n{'=' * 65}")
    print(f"PER-TYPE THRESHOLD RECOMMENDATIONS")
    print(f"{'=' * 65}")
    print(f"  (Threshold where FPR < 1% for each type)")

    for ft in sorted(set(file_types)):
        mask = file_types == ft
        ft_y = y[mask]
        ft_scores = scores[mask]
        ft_benign = ft_scores[ft_y == 0]

        if len(ft_benign) < 5:
            print(f"  {ft:15s}: insufficient benign samples ({len(ft_benign)})")
            continue

        # Find lowest threshold where FPR < 1%
        recommended = None
        for t in np.arange(0.3, 0.95, 0.01):
            fpr = (ft_benign > t).mean()
            if fpr < 0.01:
                recommended = t
                break

        if recommended:
            # Check TPR at this threshold
            ft_mal = ft_scores[ft_y == 1]
            tpr = (ft_mal > recommended).mean() if len(ft_mal) > 0 else float('nan')
            tpr_str = f"TPR={tpr:.3f}" if not np.isnan(tpr) else "TPR=N/A"
            print(f"  {ft:15s}: threshold={recommended:.2f}  FPR<1%  {tpr_str}")
        else:
            print(f"  {ft:15s}: WARNING — cannot achieve <1% FPR (benign max={ft_benign.max():.3f})")

    # ── Calibration check ────────────────────────────────────────────
    print(f"\n{'=' * 65}")
    print(f"CALIBRATION CHECK")
    print(f"{'=' * 65}")
    print(f"  (Is p(malicious)=0.7 actually correct ~70% of the time?)")

    bins = np.linspace(0, 1, 11)
    for i in range(len(bins) - 1):
        lo, hi = bins[i], bins[i + 1]
        mask = (scores >= lo) & (scores < hi)
        if mask.sum() == 0:
            continue
        actual_rate = y[mask].mean()
        predicted_mid = (lo + hi) / 2
        n = mask.sum()
        cal_error = abs(actual_rate - predicted_mid)
        indicator = "OK" if cal_error < 0.15 else "MISCAL"
        print(f"  [{lo:.1f}-{hi:.1f}]: predicted~{predicted_mid:.1f}  "
              f"actual={actual_rate:.3f}  n={n:5d}  [{indicator}]")

    return {
        "overall_auc": auc,
        "best_threshold": float(best_thresh),
        "best_f1": float(best_f1),
        "per_type": per_type_data,
    }


def evaluate_benign_dir(sess, input_name, benign_dir):
    """Evaluate on a directory of benign files (FPR-only analysis)."""
    print(f"\n  Scanning benign directory: {benign_dir}")

    files = []
    for root, dirs, fnames in os.walk(benign_dir):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fname in fnames:
            if fname.startswith("."):
                continue
            fpath = os.path.join(root, fname)
            files.append(fpath)

    print(f"  Found {len(files)} files")

    features_list = []
    file_types_list = []
    valid_files = []

    for fpath in files:
        feats = extract_features(fpath)
        if feats:
            features_list.append(feats)
            ext = Path(fpath).suffix.lstrip(".").lower()
            ft = EXT_TO_CAT.get(ext, "other")
            file_types_list.append(ft)
            valid_files.append(fpath)

    if not features_list:
        print("  No features extracted!")
        return

    X = np.array(features_list, dtype=np.float32)
    scores = run_inference(sess, input_name, X)
    file_types = np.array(file_types_list)

    print(f"\n{'=' * 65}")
    print(f"BENIGN FILE ANALYSIS (all files should score LOW)")
    print(f"{'=' * 65}")
    print(f"  Overall: mean={scores.mean():.4f}  max={scores.max():.4f}  "
          f"median={np.median(scores):.4f}")
    print(f"  Files scoring > 0.5 (false positives): "
          f"{(scores > 0.5).sum()} / {len(scores)} "
          f"({(scores > 0.5).mean() * 100:.1f}%)")

    text_histogram(scores, label="All benign")

    # Per-type breakdown
    print(f"\n  Per-type benign scores:")
    for ft in sorted(set(file_types)):
        mask = file_types == ft
        ft_scores = scores[mask]
        fp_count = (ft_scores > 0.5).sum()
        status = "OK" if fp_count == 0 else f"FP={fp_count}"
        print(f"    {ft:15s}: n={mask.sum():4d}  mean={ft_scores.mean():.4f}  "
              f"max={ft_scores.max():.4f}  [{status}]")

    # Show worst offenders
    if (scores > 0.5).sum() > 0:
        print(f"\n  Worst false positives (score > 0.5):")
        worst_idx = np.argsort(scores)[::-1]
        shown = 0
        for idx in worst_idx:
            if scores[idx] <= 0.5:
                break
            print(f"    {scores[idx]:.4f}  {file_types[idx]:15s}  {valid_files[idx]}")
            shown += 1
            if shown >= 20:
                remaining = (scores > 0.5).sum() - shown
                if remaining > 0:
                    print(f"    ... and {remaining} more")
                break


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate ONNX anomaly detection model (v2)",
    )
    parser.add_argument("--model", required=True, help="Path to ONNX model")
    parser.add_argument("--dataset", help="Path to labeled dataset CSV")
    parser.add_argument("--benign-dir", help="Directory of benign files (FPR-only)")
    parser.add_argument("--output-json", help="Save results as JSON")
    args = parser.parse_args()

    if not args.dataset and not args.benign_dir:
        print("ERROR: Provide --dataset and/or --benign-dir")
        sys.exit(1)

    print("=" * 65)
    print("Odysseus-AI Model Evaluation (v2)")
    print("=" * 65)

    # Load model
    sess, input_name = load_onnx_model(args.model)
    results = {}

    # Evaluate on labeled dataset
    if args.dataset:
        print(f"\n  Loading dataset: {args.dataset}")
        df = pd.read_csv(args.dataset)
        print(f"  Rows: {len(df)}, Labels: {df['label'].value_counts().to_dict()}")
        results["dataset"] = evaluate_from_dataset(sess, input_name, df)

    # Evaluate on benign directory
    if args.benign_dir:
        if FEATURE_NAMES is None:
            print("ERROR: generate_dataset.py not found — cannot extract features")
            sys.exit(1)
        evaluate_benign_dir(sess, input_name, args.benign_dir)

    # Save results
    if args.output_json and results:
        with open(args.output_json, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n  Results saved: {args.output_json}")

    print(f"\n{'=' * 65}")
    print("Evaluation complete.")
    print(f"{'=' * 65}")


if __name__ == "__main__":
    main()
