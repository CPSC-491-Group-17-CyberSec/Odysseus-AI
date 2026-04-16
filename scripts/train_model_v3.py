#!/usr/bin/env python3
"""
train_model_v3.py  –  Phase 4 model training.

Trains on the v3 dataset (benign + suspicious + synthetic malware).
Outputs anomaly_model_v3.onnx — does NOT overwrite v2.

Key differences from train_model.py (v2):
    - Reads 'source_class' column for stratified analysis
    - Reports separate metrics for suspicious vs synthetic_malware
    - Compares against v2 model if available
    - Saves comprehensive metadata

Usage:
    python train_model_v3.py --dataset dataset_v3.csv \\
                             --output ../data/anomaly_model_v3.onnx \\
                             --v2-model ../data/anomaly_model_v2.onnx

Requirements:
    pip install numpy pandas scikit-learn skl2onnx onnx onnxruntime
"""

import argparse
import json
import os
import sys
import warnings
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import (
    train_test_split, StratifiedKFold, cross_val_score,
)
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    accuracy_score,
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.ensemble import GradientBoostingClassifier

# Feature names — must match kFeatureNames in FeatureExtractor.h
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


def create_model():
    """Create the classifier — try XGBoost first, fall back to GradientBoosting."""
    try:
        from xgboost import XGBClassifier
        model = XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=3,
            gamma=0.1,
            reg_alpha=0.1,
            reg_lambda=1.0,
            scale_pos_weight=1.0,
            eval_metric="logloss",
            use_label_encoder=False,
            random_state=42,
            n_jobs=-1,
        )
        return model, "XGBoost"
    except ImportError:
        model = GradientBoostingClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.8,
            min_samples_leaf=5,
            random_state=42,
        )
        return model, "GradientBoosting"


def export_to_onnx(pipeline, output_path, n_features, model_name):
    """Export the trained sklearn Pipeline to ONNX format."""
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    if model_name == "XGBoost":
        try:
            import onnxmltools
        except ImportError:
            pass

    initial_type = [("features", FloatTensorType([None, n_features]))]
    try:
        onnx_model = convert_sklearn(
            pipeline, initial_types=initial_type, target_opset=13,
            options={id(pipeline): {"zipmap": False}},
        )
    except Exception:
        onnx_model = convert_sklearn(
            pipeline, initial_types=initial_type, target_opset=13,
        )

    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    size_kb = os.path.getsize(output_path) / 1024
    print(f"  ONNX model exported: {output_path} ({size_kb:.1f} KB)")
    return True


def verify_onnx(onnx_path, X_test, y_prob_sklearn):
    """Verify ONNX output matches sklearn predictions."""
    try:
        import onnxruntime as ort
    except ImportError:
        print("  onnxruntime not installed — skipping verification")
        return None

    sess = ort.InferenceSession(onnx_path)
    input_name = sess.get_inputs()[0].name
    results = sess.run(None, {input_name: X_test.astype(np.float32)})

    if len(results) >= 2:
        onnx_probs = np.array(results[1])
        if onnx_probs.ndim == 2 and onnx_probs.shape[1] >= 2:
            onnx_mal = onnx_probs[:, 1]
        else:
            onnx_mal = onnx_probs.flatten()
    else:
        onnx_mal = np.array(results[0]).flatten()

    sklearn_mal = y_prob_sklearn[:, 1] if y_prob_sklearn.ndim == 2 else y_prob_sklearn

    max_diff = np.max(np.abs(onnx_mal - sklearn_mal))
    mean_diff = np.mean(np.abs(onnx_mal - sklearn_mal))
    print(f"\n  ONNX Verification:")
    print(f"    Max |ONNX - sklearn|:  {max_diff:.6f}")
    print(f"    Mean |ONNX - sklearn|: {mean_diff:.6f}")
    if max_diff > 0.01:
        print(f"    WARNING: ONNX output diverges!")
    else:
        print(f"    ONNX verification PASSED")

    return onnx_mal


def compare_with_v2(v2_path, X_test, y_test, source_classes):
    """Run v2 model on the same test set and compare scores."""
    try:
        import onnxruntime as ort
    except ImportError:
        print("  onnxruntime not installed — skipping v2 comparison")
        return

    if not os.path.exists(v2_path):
        print(f"  v2 model not found at {v2_path} — skipping comparison")
        return

    print(f"\n{'=' * 65}")
    print(f"V2 vs V3 COMPARISON")
    print(f"{'=' * 65}")

    sess = ort.InferenceSession(v2_path)
    input_name = sess.get_inputs()[0].name
    results = sess.run(None, {input_name: X_test.astype(np.float32)})

    if len(results) >= 2:
        v2_probs = np.array(results[1])
        v2_scores = v2_probs[:, 1] if v2_probs.ndim == 2 else v2_probs.flatten()
    else:
        v2_scores = np.array(results[0]).flatten()

    v2_pred = (v2_scores > 0.5).astype(int)
    v2_acc = accuracy_score(y_test, v2_pred)
    try:
        v2_auc = roc_auc_score(y_test, v2_scores)
    except ValueError:
        v2_auc = float('nan')

    print(f"  v2 Accuracy: {v2_acc:.4f}   ROC-AUC: {v2_auc:.4f}")

    # Per-source-class comparison
    for src in sorted(set(source_classes)):
        mask = source_classes == src
        if mask.sum() == 0:
            continue
        src_scores = v2_scores[mask]
        src_y = y_test[mask]
        benign_mask = src_y == 0
        mal_mask = src_y == 1

        print(f"\n  {src} (n={mask.sum()}):")
        if benign_mask.sum() > 0:
            fpr = (src_scores[benign_mask] > 0.5).mean()
            print(f"    v2 Benign mean={src_scores[benign_mask].mean():.4f}  FPR@0.5={fpr:.4f}")
        if mal_mask.sum() > 0:
            tpr = (src_scores[mal_mask] > 0.5).mean()
            print(f"    v2 Flagged mean={src_scores[mal_mask].mean():.4f}  TPR@0.5={tpr:.4f}")

    return v2_scores


def main():
    parser = argparse.ArgumentParser(
        description="Train anomaly detection model v3 (Phase 4)",
    )
    parser.add_argument("--dataset", required=True, help="Path to v3 dataset CSV")
    parser.add_argument("--output", default="../data/anomaly_model_v3.onnx",
                        help="Output ONNX model path")
    parser.add_argument("--v2-model", default="../data/anomaly_model_v2.onnx",
                        help="Path to v2 model for comparison")
    parser.add_argument("--test-size", type=float, default=0.2)
    args = parser.parse_args()

    print("=" * 65)
    print("Odysseus-AI Model Training (Phase 4 / v3)")
    print("=" * 65)

    # ── Load dataset ─────────────────────────────────────────────────
    print(f"\nLoading dataset: {args.dataset}")
    df = pd.read_csv(args.dataset)
    print(f"  Rows: {len(df)}")
    print(f"  Labels: {df['label'].value_counts().to_dict()}")

    has_source = "source_class" in df.columns
    if has_source:
        print(f"  Source classes: {df['source_class'].value_counts().to_dict()}")

    has_file_type = "file_type" in df.columns
    if has_file_type:
        print(f"  File types: {df['file_type'].value_counts().to_dict()}")

    # ── Prepare features ─────────────────────────────────────────────
    feature_cols = [c for c in df.columns
                    if c not in ("label", "file_type", "source_class", "file_path")]
    X = df[feature_cols].values.astype(np.float32)
    y = df["label"].values
    n_features = X.shape[1]

    print(f"  Features: {n_features}")
    if n_features != 38:
        print(f"  WARNING: Expected 38, got {n_features}. C++ expects 38.")

    source_classes = df["source_class"].values if has_source else np.array(["unknown"] * len(df))
    file_types = df["file_type"].values if has_file_type else np.array(["unknown"] * len(df))

    # ── Class balance ────────────────────────────────────────────────
    n_benign = (y == 0).sum()
    n_mal = (y == 1).sum()
    class_ratio = n_benign / max(n_mal, 1)
    print(f"  Class ratio (benign/flagged): {class_ratio:.2f}")

    # ── Train/test split ─────────────────────────────────────────────
    X_train, X_test, y_train, y_test, src_train, src_test, ft_train, ft_test = \
        train_test_split(X, y, source_classes, file_types,
                         test_size=args.test_size, random_state=42, stratify=y)

    print(f"\n  Train: {len(X_train)} samples")
    print(f"  Test:  {len(X_test)} samples")

    # ── Create and train ─────────────────────────────────────────────
    model, model_name = create_model()
    print(f"\n  Model: {model_name}")

    if model_name == "XGBoost" and abs(class_ratio - 1.0) > 0.3:
        model.set_params(scale_pos_weight=class_ratio)
        print(f"  scale_pos_weight set to {class_ratio:.2f}")

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", model),
    ])

    # Cross-validation
    print(f"\n  Running 5-fold cross-validation...")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="roc_auc")
    print(f"  CV ROC-AUC: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    # Train final model
    print(f"\n  Training final model...")
    pipeline.fit(X_train, y_train)

    # ── Evaluate ─────────────────────────────────────────────────────
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)
    mal_scores = y_prob[:, 1]

    print(f"\n{'=' * 65}")
    print(f"TEST SET RESULTS (v3 — {model_name})")
    print(f"{'=' * 65}")
    print(f"  Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"  ROC-AUC:   {roc_auc_score(y_test, mal_scores):.4f}")
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Flagged"]))

    cm = confusion_matrix(y_test, y_pred)
    fpr = cm[0, 1] / max(cm[0, 0] + cm[0, 1], 1)
    tpr = cm[1, 1] / max(cm[1, 0] + cm[1, 1], 1)
    print(f"  Confusion Matrix:")
    print(f"    TN={cm[0,0]:5d}  FP={cm[0,1]:5d}  (FPR={fpr:.4f})")
    print(f"    FN={cm[1,0]:5d}  TP={cm[1,1]:5d}  (TPR={tpr:.4f})")

    # ── Per-source-class analysis ────────────────────────────────────
    print(f"\n{'=' * 65}")
    print(f"PER-SOURCE-CLASS ANALYSIS")
    print(f"{'=' * 65}")

    per_source = {}
    for src in sorted(set(src_test)):
        mask = src_test == src
        if mask.sum() == 0:
            continue
        src_scores = mal_scores[mask]
        src_y = y_test[mask]
        benign_mask = src_y == 0
        mal_mask = src_y == 1

        src_fpr = (src_scores[benign_mask] > 0.5).mean() if benign_mask.sum() > 0 else float('nan')
        src_tpr = (src_scores[mal_mask] > 0.5).mean() if mal_mask.sum() > 0 else float('nan')

        print(f"\n  {src} (n={mask.sum()}, benign={benign_mask.sum()}, flagged={mal_mask.sum()}):")
        print(f"    mean_score={src_scores.mean():.4f}  std={src_scores.std():.4f}")
        if not np.isnan(src_fpr):
            print(f"    FPR@0.5={src_fpr:.4f}")
        if not np.isnan(src_tpr):
            print(f"    TPR@0.5={src_tpr:.4f}")

        per_source[src] = {
            "n": int(mask.sum()),
            "n_benign": int(benign_mask.sum()),
            "n_flagged": int(mal_mask.sum()),
            "mean_score": float(src_scores.mean()),
            "fpr": float(src_fpr) if not np.isnan(src_fpr) else None,
            "tpr": float(src_tpr) if not np.isnan(src_tpr) else None,
        }

    # ── Score distributions ──────────────────────────────────────────
    print(f"\n{'=' * 65}")
    print(f"SCORE DISTRIBUTIONS")
    print(f"{'=' * 65}")
    benign_scores = mal_scores[y_test == 0]
    flagged_scores = mal_scores[y_test == 1]
    print(f"  Benign:  mean={benign_scores.mean():.4f}  std={benign_scores.std():.4f}  "
          f"max={benign_scores.max():.4f}")
    print(f"  Flagged: mean={flagged_scores.mean():.4f}  std={flagged_scores.std():.4f}  "
          f"min={flagged_scores.min():.4f}")
    gap = flagged_scores.min() - benign_scores.max()
    print(f"  Score gap: {gap:.4f}")

    # ── Feature importance ───────────────────────────────────────────
    classifier = pipeline.named_steps["classifier"]
    if hasattr(classifier, "feature_importances_"):
        importances = classifier.feature_importances_
        sorted_idx = np.argsort(importances)[::-1]
        print(f"\n  Top 10 Features:")
        for i in range(min(10, len(sorted_idx))):
            idx = sorted_idx[i]
            name = feature_cols[idx] if idx < len(feature_cols) else f"feature_{idx}"
            print(f"    {name:30s}  {importances[idx]:.4f}")

    # ── Export to ONNX ───────────────────────────────────────────────
    print(f"\n  Exporting to ONNX...")
    output_dir = Path(args.output).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    success = export_to_onnx(pipeline, args.output, n_features, model_name)
    if success:
        verify_onnx(args.output, X_test, y_prob)

    # ── Compare with v2 ──────────────────────────────────────────────
    compare_with_v2(args.v2_model, X_test, y_test, src_test)

    # ── Save metadata ────────────────────────────────────────────────
    metadata = {
        "version": "v3",
        "phase": 4,
        "trained_at": datetime.now().isoformat(),
        "model_type": model_name,
        "n_features": n_features,
        "feature_names": feature_cols,
        "dataset": args.dataset,
        "dataset_size": len(df),
        "n_benign": int(n_benign),
        "n_flagged": int(n_mal),
        "train_size": len(X_train),
        "test_size_count": len(X_test),
        "cv_roc_auc_mean": float(cv_scores.mean()),
        "cv_roc_auc_std": float(cv_scores.std()),
        "test_accuracy": float(accuracy_score(y_test, y_pred)),
        "test_roc_auc": float(roc_auc_score(y_test, mal_scores)),
        "confusion_matrix": {"TN": int(cm[0, 0]), "FP": int(cm[0, 1]),
                             "FN": int(cm[1, 0]), "TP": int(cm[1, 1])},
        "fpr": float(fpr),
        "tpr": float(tpr),
        "per_source_class": per_source,
        "score_stats": {
            "benign_mean": float(benign_scores.mean()),
            "benign_max": float(benign_scores.max()),
            "flagged_mean": float(flagged_scores.mean()),
            "flagged_min": float(flagged_scores.min()),
            "score_gap": float(gap),
        },
    }

    meta_path = str(args.output).replace(".onnx", "_metadata.json")
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"\n  Metadata saved: {meta_path}")

    print(f"\n{'=' * 65}")
    print(f"Done! v3 model saved to {args.output}")
    print(f"v2 model preserved at: {args.v2_model}")
    print(f"{'=' * 65}")


if __name__ == "__main__":
    main()
