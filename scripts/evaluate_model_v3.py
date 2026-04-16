#!/usr/bin/env python3
"""
evaluate_model_v3.py  –  Phase 4 evaluation with v2 comparison.

Reports:
    1. Benign false positive rate (overall and per file-type)
    2. Suspicious detection rate (the new real-file suspicious class)
    3. Score distributions by source_class
    4. Side-by-side v2 vs v3 comparison
    5. Threshold sweep with recommendations

Usage:
    python evaluate_model_v3.py \\
        --v3-model ../data/anomaly_model_v3.onnx \\
        --v2-model ../data/anomaly_model_v2.onnx \\
        --dataset  dataset_v3.csv
"""

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd


def load_onnx(path):
    """Load ONNX model and return (session, input_name)."""
    import onnxruntime as ort
    sess = ort.InferenceSession(path)
    return sess, sess.get_inputs()[0].name


def score(sess, input_name, X):
    """Run inference, return p(flagged) scores."""
    results = sess.run(None, {input_name: X.astype(np.float32)})
    if len(results) >= 2:
        probs = np.array(results[1])
        return probs[:, 1] if (probs.ndim == 2 and probs.shape[1] >= 2) else probs.flatten()
    return np.array(results[0]).flatten()


def text_histogram(values, label="", bins=20, width=50):
    if len(values) == 0:
        print(f"    {label}: (no data)")
        return
    hist, edges = np.histogram(values, bins=bins, range=(0.0, 1.0))
    mx = max(hist) if max(hist) > 0 else 1
    print(f"\n    {label} (n={len(values)}, mean={values.mean():.3f}, "
          f"std={values.std():.3f}, min={values.min():.3f}, max={values.max():.3f})")
    for i in range(len(hist)):
        bar = "#" * int(hist[i] / mx * width)
        if hist[i] > 0:
            print(f"      [{edges[i]:.2f}-{edges[i+1]:.2f}] {hist[i]:5d} {bar}")


def main():
    parser = argparse.ArgumentParser(description="Phase 4 model evaluation")
    parser.add_argument("--v3-model", required=True, help="Path to v3 ONNX model")
    parser.add_argument("--v2-model", help="Path to v2 ONNX model (for comparison)")
    parser.add_argument("--dataset", required=True, help="Path to labeled CSV")
    parser.add_argument("--output-json", help="Save results as JSON")
    args = parser.parse_args()

    print("=" * 70)
    print("Odysseus-AI Model Evaluation (Phase 4 / v3)")
    print("=" * 70)

    # ── Load dataset ─────────────────────────────────────────────────
    df = pd.read_csv(args.dataset)
    feature_cols = [c for c in df.columns
                    if c not in ("label", "file_type", "source_class", "file_path")]
    X = df[feature_cols].values.astype(np.float32)
    y = df["label"].values
    source = df["source_class"].values if "source_class" in df.columns else np.array(["unknown"] * len(df))
    ftypes = df["file_type"].values if "file_type" in df.columns else np.array(["unknown"] * len(df))

    print(f"  Dataset: {args.dataset}")
    print(f"  Samples: {len(df)}")
    print(f"  Labels:  {dict(zip(*np.unique(y, return_counts=True)))}")
    print(f"  Sources: {dict(zip(*np.unique(source, return_counts=True)))}")

    # ── Load v3 model ────────────────────────────────────────────────
    print(f"\n  Loading v3: {args.v3_model}")
    v3_sess, v3_input = load_onnx(args.v3_model)
    v3_scores = score(v3_sess, v3_input, X)

    # ── Load v2 model (optional) ─────────────────────────────────────
    v2_scores = None
    if args.v2_model and os.path.exists(args.v2_model):
        print(f"  Loading v2: {args.v2_model}")
        v2_sess, v2_input = load_onnx(args.v2_model)
        v2_scores = score(v2_sess, v2_input, X)

    results = {}

    # ══════════════════════════════════════════════════════════════════
    # 1. BENIGN FALSE POSITIVE RATE
    # ══════════════════════════════════════════════════════════════════
    print(f"\n{'=' * 70}")
    print(f"1. BENIGN FALSE POSITIVE RATE")
    print(f"{'=' * 70}")

    benign_mask = y == 0
    benign_v3 = v3_scores[benign_mask]
    fpr_v3 = (benign_v3 > 0.5).mean()
    print(f"  v3 overall: {fpr_v3*100:.2f}% FPR  "
          f"(mean={benign_v3.mean():.4f}, max={benign_v3.max():.4f})")

    if v2_scores is not None:
        benign_v2 = v2_scores[benign_mask]
        fpr_v2 = (benign_v2 > 0.5).mean()
        print(f"  v2 overall: {fpr_v2*100:.2f}% FPR  "
              f"(mean={benign_v2.mean():.4f}, max={benign_v2.max():.4f})")
        delta = fpr_v3 - fpr_v2
        direction = "WORSE" if delta > 0 else "BETTER" if delta < 0 else "SAME"
        print(f"  Delta: {delta*100:+.2f}pp ({direction})")

    # Per file-type benign FPR
    print(f"\n  Per-type benign FPR (v3):")
    for ft in sorted(set(ftypes[benign_mask])):
        ft_mask = benign_mask & (ftypes == ft)
        ft_scores_v3 = v3_scores[ft_mask]
        ft_fpr = (ft_scores_v3 > 0.5).mean()
        status = "OK" if ft_fpr == 0 else f"FP={int(ft_fpr * ft_mask.sum())}"
        line = f"    {ft:15s}: n={ft_mask.sum():4d}  mean={ft_scores_v3.mean():.4f}  max={ft_scores_v3.max():.4f}  [{status}]"
        if v2_scores is not None:
            ft_scores_v2 = v2_scores[ft_mask]
            ft_fpr_v2 = (ft_scores_v2 > 0.5).mean()
            line += f"  (v2 FPR={ft_fpr_v2*100:.1f}%)"
        print(line)

    results["benign_fpr_v3"] = float(fpr_v3)

    # ══════════════════════════════════════════════════════════════════
    # 2. SUSPICIOUS DETECTION RATE
    # ══════════════════════════════════════════════════════════════════
    print(f"\n{'=' * 70}")
    print(f"2. SUSPICIOUS DETECTION RATE")
    print(f"{'=' * 70}")

    susp_mask = source == "suspicious"
    if susp_mask.sum() > 0:
        susp_v3 = v3_scores[susp_mask]
        tpr_susp_v3 = (susp_v3 > 0.5).mean()
        print(f"  v3 suspicious: {tpr_susp_v3*100:.1f}% detected  "
              f"(mean={susp_v3.mean():.4f}, min={susp_v3.min():.4f})")

        if v2_scores is not None:
            susp_v2 = v2_scores[susp_mask]
            tpr_susp_v2 = (susp_v2 > 0.5).mean()
            print(f"  v2 suspicious: {tpr_susp_v2*100:.1f}% detected  "
                  f"(mean={susp_v2.mean():.4f}, min={susp_v2.min():.4f})")

        results["suspicious_tpr_v3"] = float(tpr_susp_v3)
    else:
        print(f"  No suspicious samples in dataset")

    # Synthetic malware detection
    synth_mal_mask = source == "synthetic_malware"
    if synth_mal_mask.sum() > 0:
        synth_v3 = v3_scores[synth_mal_mask]
        tpr_synth_v3 = (synth_v3 > 0.5).mean()
        print(f"  v3 synthetic_malware: {tpr_synth_v3*100:.1f}% detected  "
              f"(mean={synth_v3.mean():.4f}, min={synth_v3.min():.4f})")
        results["synth_malware_tpr_v3"] = float(tpr_synth_v3)

    # ══════════════════════════════════════════════════════════════════
    # 3. SCORE DISTRIBUTIONS
    # ══════════════════════════════════════════════════════════════════
    print(f"\n{'=' * 70}")
    print(f"3. SCORE DISTRIBUTIONS (v3)")
    print(f"{'=' * 70}")

    for src in sorted(set(source)):
        mask = source == src
        text_histogram(v3_scores[mask], label=f"v3 — {src}")

    if v2_scores is not None:
        print(f"\n  Score Distributions (v2):")
        for src in sorted(set(source)):
            mask = source == src
            text_histogram(v2_scores[mask], label=f"v2 — {src}")

    # ══════════════════════════════════════════════════════════════════
    # 4. V2 vs V3 SIDE-BY-SIDE
    # ══════════════════════════════════════════════════════════════════
    if v2_scores is not None:
        print(f"\n{'=' * 70}")
        print(f"4. V2 vs V3 SIDE-BY-SIDE")
        print(f"{'=' * 70}")
        print(f"  {'Metric':25s} {'v2':>10s} {'v3':>10s} {'Delta':>10s}")
        print(f"  {'-' * 55}")

        v2_acc = ((v2_scores > 0.5).astype(int) == y).mean()
        v3_acc = ((v3_scores > 0.5).astype(int) == y).mean()
        print(f"  {'Accuracy':25s} {v2_acc:10.4f} {v3_acc:10.4f} {v3_acc-v2_acc:+10.4f}")

        # AUC via trapezoidal rule (no sklearn)
        def compute_auc(labels, scores):
            desc = np.argsort(-scores)
            labels_s = labels[desc]
            n_pos = labels.sum()
            n_neg = len(labels) - n_pos
            if n_pos == 0 or n_neg == 0:
                return float('nan')
            tp, fp, auc = 0, 0, 0.0
            prev_fp = 0
            for i in range(len(labels_s)):
                if labels_s[i] == 1:
                    tp += 1
                else:
                    fp += 1
                    auc += tp
            return auc / (n_pos * n_neg)

        try:
            v2_auc = compute_auc(y, v2_scores)
            v3_auc = compute_auc(y, v3_scores)
            print(f"  {'ROC-AUC':25s} {v2_auc:10.4f} {v3_auc:10.4f} {v3_auc-v2_auc:+10.4f}")
        except Exception:
            pass

        v2_fpr_all = (v2_scores[benign_mask] > 0.5).mean()
        v3_fpr_all = (v3_scores[benign_mask] > 0.5).mean()
        print(f"  {'Benign FPR':25s} {v2_fpr_all:10.4f} {v3_fpr_all:10.4f} {v3_fpr_all-v2_fpr_all:+10.4f}")

        flagged_mask = y == 1
        v2_tpr_all = (v2_scores[flagged_mask] > 0.5).mean()
        v3_tpr_all = (v3_scores[flagged_mask] > 0.5).mean()
        print(f"  {'Flagged TPR':25s} {v2_tpr_all:10.4f} {v3_tpr_all:10.4f} {v3_tpr_all-v2_tpr_all:+10.4f}")

        results["v2_v3_comparison"] = {
            "v2_accuracy": float(v2_acc), "v3_accuracy": float(v3_acc),
            "v2_fpr": float(v2_fpr_all), "v3_fpr": float(v3_fpr_all),
            "v2_tpr": float(v2_tpr_all), "v3_tpr": float(v3_tpr_all),
        }

    # ══════════════════════════════════════════════════════════════════
    # 5. THRESHOLD SWEEP
    # ══════════════════════════════════════════════════════════════════
    print(f"\n{'=' * 70}")
    print(f"5. THRESHOLD SWEEP (v3)")
    print(f"{'=' * 70}")
    print(f"  {'Threshold':>10s} {'FP':>5s} {'FN':>5s} {'FPR':>7s} {'TPR':>7s}")
    print(f"  {'-' * 40}")

    for t in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
        v3_pred = (v3_scores > t).astype(int)
        fp = ((v3_pred == 1) & (y == 0)).sum()
        fn = ((v3_pred == 0) & (y == 1)).sum()
        t_fpr = fp / max((y == 0).sum(), 1)
        t_tpr = ((v3_pred == 1) & (y == 1)).sum() / max((y == 1).sum(), 1)
        print(f"  {t:10.2f} {fp:5d} {fn:5d} {t_fpr:7.4f} {t_tpr:7.4f}")

    # ── Save results ─────────────────────────────────────────────────
    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n  Results saved: {args.output_json}")

    print(f"\n{'=' * 70}")
    print("Evaluation complete.")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
