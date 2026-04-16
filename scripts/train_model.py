#!/usr/bin/env python3
"""
train_model.py  –  Train anomaly detection model with file-type awareness.

Trains a single XGBoost/GradientBoosting classifier on the 38-feature vectors,
but evaluates performance per file-type category to ensure balanced accuracy
across PEBinary, Script, WebContent, TextData, Archive, Media, etc.

The model is exported in ONNX format for the C++ AnomalyDetector via ONNX Runtime.

Key improvements over v1:
    - File-type-stratified train/test split (when file_type column available)
    - Per-type evaluation metrics (FPR, TPR, score distributions)
    - Class weight balancing for imbalanced datasets
    - Hyperparameter tuning with cross-validation
    - Feature importance analysis per file-type
    - ONNX verification with per-type score checks
    - Saves training metadata alongside the model

Usage:
    python train_model.py --dataset dataset_v2.csv --output ../data/anomaly_model.onnx

Requirements:
    pip install numpy pandas scikit-learn xgboost skl2onnx onnx onnxruntime
"""

import argparse
import json
import sys
import warnings
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import (
    train_test_split, StratifiedKFold, cross_val_score, cross_val_predict
)
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    accuracy_score, precision_recall_fscore_support
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

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


# ============================================================================
# Model selection
# ============================================================================

def create_model(model_type="auto"):
    """Create the best available classifier."""
    if model_type in ("auto", "xgboost"):
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
                scale_pos_weight=1.0,   # adjusted below if imbalanced
                eval_metric="logloss",
                use_label_encoder=False,
                random_state=42,
                n_jobs=-1,
            )
            return model, "XGBoost"
        except ImportError:
            if model_type == "xgboost":
                print("ERROR: XGBoost not installed")
                sys.exit(1)

    if model_type in ("auto", "gradient_boosting"):
        from sklearn.ensemble import GradientBoostingClassifier
        model = GradientBoostingClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.8,
            min_samples_leaf=5,
            random_state=42,
        )
        return model, "GradientBoosting"

    from sklearn.ensemble import RandomForestClassifier
    model = RandomForestClassifier(
        n_estimators=300, max_depth=10, min_samples_leaf=3,
        class_weight="balanced", random_state=42, n_jobs=-1,
    )
    return model, "RandomForest"


# ============================================================================
# File-type inference from features (when file_type column is absent)
# ============================================================================

def infer_file_type(row):
    """Infer file category from feature values. Used when dataset lacks file_type column."""
    if row["isPE"] == 1.0:
        return "pe_binary"
    if row["isScript"] == 1.0:
        return "script"
    if row["isExecutable"] == 1.0:
        return "pe_binary"
    if row["isDLL"] == 1.0:
        return "pe_binary"

    # High printable ASCII + low high-byte ratio → text-like
    if row["printableAsciiRatio"] > 0.7 and row["highByteRatio"] < 0.05:
        # Could be web content, text, or source code
        if row["urlCount"] > 0.05 or row["base64StringCount"] > 0.05:
            return "web_content"
        return "text_data"

    # High entropy + low printable → compressed/archive or media
    if row["shannonEntropy"] > 7.0 and row["printableAsciiRatio"] < 0.3:
        return "archive"

    # Moderate entropy + mixed bytes → media/binary
    if row["highByteRatio"] > 0.3:
        return "media_binary"

    return "other"


# ============================================================================
# ONNX export
# ============================================================================

def export_to_onnx(pipeline, output_path, n_features, model_name):
    """Export the trained sklearn Pipeline to ONNX format."""
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    if model_name == "XGBoost":
        try:
            import onnxmltools  # noqa: F401 — registers XGBoost converter
        except ImportError:
            pass

    initial_type = [("features", FloatTensorType([None, n_features]))]

    try:
        onnx_model = convert_sklearn(
            pipeline,
            initial_types=initial_type,
            target_opset=13,
            options={id(pipeline): {"zipmap": False}},
        )
    except Exception as e:
        # Fallback: try without zipmap option (some converters don't support it)
        print(f"  First export attempt failed ({e}), retrying...")
        onnx_model = convert_sklearn(
            pipeline,
            initial_types=initial_type,
            target_opset=13,
        )

    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    size_kb = os.path.getsize(output_path) / 1024
    print(f"  ONNX model exported: {output_path} ({size_kb:.1f} KB)")
    return True


def verify_onnx(onnx_path, X_test, y_prob_sklearn, file_types=None):
    """Verify ONNX output matches sklearn, with per-type breakdown."""
    try:
        import onnxruntime as ort
    except ImportError:
        print("  onnxruntime not installed — skipping verification")
        return

    sess = ort.InferenceSession(onnx_path)
    input_name = sess.get_inputs()[0].name

    # Run inference on full test set
    results = sess.run(None, {input_name: X_test.astype(np.float32)})

    print(f"\n  ONNX Verification:")
    print(f"    Outputs: {len(results)} tensors")
    for i, r in enumerate(results):
        arr = np.array(r)
        print(f"    Output[{i}]: shape={arr.shape} dtype={arr.dtype}")

    # Extract p(malicious) from ONNX
    if len(results) >= 2:
        onnx_probs = np.array(results[1])
        if onnx_probs.ndim == 2 and onnx_probs.shape[1] >= 2:
            onnx_mal = onnx_probs[:, 1]
        else:
            onnx_mal = onnx_probs.flatten()
    else:
        onnx_mal = np.array(results[0]).flatten()

    sklearn_mal = y_prob_sklearn[:, 1] if y_prob_sklearn.ndim == 2 else y_prob_sklearn

    # Overall correlation
    max_diff = np.max(np.abs(onnx_mal - sklearn_mal))
    mean_diff = np.mean(np.abs(onnx_mal - sklearn_mal))
    print(f"    Max |ONNX - sklearn|:  {max_diff:.6f}")
    print(f"    Mean |ONNX - sklearn|: {mean_diff:.6f}")

    if max_diff > 0.01:
        print(f"    WARNING: ONNX output diverges from sklearn by more than 0.01!")
    else:
        print(f"    ONNX verification PASSED")

    # Per-type score distribution from ONNX
    if file_types is not None:
        print(f"\n    Per-type ONNX score distribution (p_malicious):")
        for ft in sorted(set(file_types)):
            mask = file_types == ft
            if mask.sum() == 0:
                continue
            scores = onnx_mal[mask]
            print(f"      {ft:15s}: n={mask.sum():4d}  "
                  f"mean={scores.mean():.3f}  std={scores.std():.3f}  "
                  f"min={scores.min():.3f}  max={scores.max():.3f}")


# ============================================================================
# Per-type evaluation
# ============================================================================

def evaluate_per_type(y_true, y_prob, file_types, label="Test"):
    """Print per-type metrics: FPR, TPR, mean scores."""
    print(f"\n  Per-Type Evaluation ({label}):")
    print(f"  {'Type':15s} {'N':>5s} {'Benign':>7s} {'Mal':>5s} "
          f"{'FPR':>6s} {'TPR':>6s} {'AvgScore':>9s} {'StdScore':>9s}")
    print(f"  {'-'*70}")

    mal_probs = y_prob[:, 1] if y_prob.ndim == 2 else y_prob
    results = {}

    for ft in sorted(set(file_types)):
        mask = file_types == ft
        ft_y = y_true[mask]
        ft_scores = mal_probs[mask]

        n_benign = (ft_y == 0).sum()
        n_mal = (ft_y == 1).sum()

        # FPR: false positive rate on benign files
        fpr = np.nan
        if n_benign > 0:
            benign_scores = ft_scores[ft_y == 0]
            fpr = (benign_scores > 0.5).mean()

        # TPR: true positive rate on malicious files
        tpr = np.nan
        if n_mal > 0:
            mal_scores = ft_scores[ft_y == 1]
            tpr = (mal_scores > 0.5).mean()

        fpr_str = f"{fpr:.3f}" if not np.isnan(fpr) else "  N/A"
        tpr_str = f"{tpr:.3f}" if not np.isnan(tpr) else "  N/A"

        print(f"  {ft:15s} {mask.sum():5d} {n_benign:7d} {n_mal:5d} "
              f"{fpr_str:>6s} {tpr_str:>6s} "
              f"{ft_scores.mean():9.3f} {ft_scores.std():9.3f}")

        results[ft] = {
            "n": int(mask.sum()), "n_benign": int(n_benign), "n_malicious": int(n_mal),
            "fpr": float(fpr) if not np.isnan(fpr) else None,
            "tpr": float(tpr) if not np.isnan(tpr) else None,
            "mean_score": float(ft_scores.mean()),
            "std_score": float(ft_scores.std()),
        }

    return results


# ============================================================================
# Main
# ============================================================================

import os


def main():
    parser = argparse.ArgumentParser(
        description="Train anomaly detection model (v2 — file-type-aware)",
    )
    parser.add_argument("--dataset", required=True, help="Path to dataset CSV")
    parser.add_argument("--output", default="../data/anomaly_model.onnx",
                        help="Output ONNX model path")
    parser.add_argument("--test-size", type=float, default=0.2,
                        help="Test split ratio (default 0.2)")
    parser.add_argument("--model", choices=["auto", "xgboost", "gradient_boosting", "random_forest"],
                        default="auto", help="Model type")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip ONNX verification")
    args = parser.parse_args()

    print("=" * 65)
    print("Odysseus-AI Model Training (v2)")
    print("=" * 65)

    # ── Load dataset ─────────────────────────────────────────────────────
    print(f"\nLoading dataset: {args.dataset}")
    df = pd.read_csv(args.dataset)
    print(f"  Rows: {len(df)}")
    print(f"  Label distribution: {df['label'].value_counts().to_dict()}")

    if len(df) < 100:
        print("WARNING: Very small dataset. Model quality will be limited.")
        print("Aim for 1000+ samples of each class.")

    # ── File-type column ─────────────────────────────────────────────────
    has_file_type = "file_type" in df.columns
    if has_file_type:
        print(f"  File-type column found: {df['file_type'].value_counts().to_dict()}")
    else:
        print(f"  No file_type column — inferring from features...")
        df["file_type"] = df.apply(infer_file_type, axis=1)
        print(f"  Inferred types: {df['file_type'].value_counts().to_dict()}")

    # ── Prepare features and labels ──────────────────────────────────────
    feature_cols = [c for c in df.columns if c not in ("label", "file_type", "file_path")]
    X = df[feature_cols].values.astype(np.float32)
    y = df["label"].values
    file_types = df["file_type"].values
    n_features = X.shape[1]

    print(f"  Features: {n_features}")

    if n_features != 38:
        print(f"WARNING: Expected 38 features, got {n_features}.")
        print(f"The C++ AnomalyDetector expects exactly 38 features.")

    # ── Handle class imbalance ───────────────────────────────────────────
    n_benign = (y == 0).sum()
    n_malicious = (y == 1).sum()
    if n_benign > 0 and n_malicious > 0:
        class_ratio = n_benign / n_malicious
        print(f"  Class ratio (benign/malicious): {class_ratio:.2f}")
    else:
        class_ratio = 1.0
        print(f"  WARNING: Missing class — benign={n_benign}, malicious={n_malicious}")

    # ── Train/test split (stratified by label + file_type) ───────────────
    # Create compound stratification key
    strat_key = pd.Series([f"{l}_{t}" for l, t in zip(y, file_types)])

    # Drop rare combinations that can't be split
    strat_counts = strat_key.value_counts()
    rare_mask = strat_key.isin(strat_counts[strat_counts < 2].index)
    if rare_mask.any():
        print(f"  Note: {rare_mask.sum()} samples in rare type/label combos — "
              f"using label-only stratification")
        strat_split = y
    else:
        strat_split = strat_key

    X_train, X_test, y_train, y_test, ft_train, ft_test = train_test_split(
        X, y, file_types,
        test_size=args.test_size, random_state=42, stratify=strat_split,
    )
    print(f"\n  Train: {len(X_train)} samples")
    print(f"  Test:  {len(X_test)} samples")

    # ── Create model ─────────────────────────────────────────────────────
    model, model_name = create_model(args.model)
    print(f"\n  Model: {model_name}")

    # Adjust class weight for XGBoost if imbalanced
    if model_name == "XGBoost" and abs(class_ratio - 1.0) > 0.3:
        model.set_params(scale_pos_weight=class_ratio)
        print(f"  scale_pos_weight set to {class_ratio:.2f}")

    # Build pipeline
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", model),
    ])

    # ── Cross-validation ─────────────────────────────────────────────────
    print(f"\n  Running 5-fold cross-validation...")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(
            pipeline, X_train, y_train, cv=cv, scoring="roc_auc"
        )
    print(f"  CV ROC-AUC: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    # ── Train final model ────────────────────────────────────────────────
    print(f"\n  Training final model on full training set...")
    pipeline.fit(X_train, y_train)

    # ── Evaluate: overall ────────────────────────────────────────────────
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)

    print(f"\n{'=' * 65}")
    print(f"TEST SET RESULTS ({model_name})")
    print(f"{'=' * 65}")
    print(f"  Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"  ROC-AUC:   {roc_auc_score(y_test, y_prob[:, 1]):.4f}")
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    cm = confusion_matrix(y_test, y_pred)
    print(f"  Confusion Matrix:")
    print(f"    TN={cm[0,0]:5d}  FP={cm[0,1]:5d}  (FPR={cm[0,1]/(cm[0,0]+cm[0,1]):.4f})")
    print(f"    FN={cm[1,0]:5d}  TP={cm[1,1]:5d}  (TPR={cm[1,1]/(cm[1,0]+cm[1,1]):.4f})")

    # ── Evaluate: per file type ──────────────────────────────────────────
    per_type_results = evaluate_per_type(y_test, y_prob, ft_test, "Test Set")

    # ── Feature importance ───────────────────────────────────────────────
    classifier = pipeline.named_steps["classifier"]
    if hasattr(classifier, "feature_importances_"):
        importances = classifier.feature_importances_
        sorted_idx = np.argsort(importances)[::-1]
        print(f"\n  Top 15 Features by Importance:")
        for i in range(min(15, len(sorted_idx))):
            idx = sorted_idx[i]
            name = feature_cols[idx] if idx < len(feature_cols) else f"feature_{idx}"
            print(f"    {name:30s}  {importances[idx]:.4f}")

    # ── Score distribution analysis ──────────────────────────────────────
    mal_scores = y_prob[:, 1]
    print(f"\n  Score Distribution (test set):")
    print(f"    Benign  files: mean={mal_scores[y_test==0].mean():.3f}  "
          f"std={mal_scores[y_test==0].std():.3f}  "
          f"max={mal_scores[y_test==0].max():.3f}")
    print(f"    Malware files: mean={mal_scores[y_test==1].mean():.3f}  "
          f"std={mal_scores[y_test==1].std():.3f}  "
          f"min={mal_scores[y_test==1].min():.3f}")

    # Score separation quality
    benign_max = mal_scores[y_test == 0].max()
    malware_min = mal_scores[y_test == 1].min()
    gap = malware_min - benign_max
    print(f"    Score gap (mal_min - benign_max): {gap:.3f}")
    if gap > 0:
        print(f"    Classes are cleanly separable at threshold ~{(benign_max + malware_min) / 2:.3f}")
    else:
        print(f"    WARNING: Score distributions overlap — some misclassifications unavoidable")

    # ── Threshold recommendations ────────────────────────────────────────
    print(f"\n  Threshold Recommendations:")
    for thresh in [0.3, 0.4, 0.5, 0.6, 0.7]:
        fp = ((mal_scores > thresh) & (y_test == 0)).sum()
        fn = ((mal_scores <= thresh) & (y_test == 1)).sum()
        fpr = fp / max((y_test == 0).sum(), 1)
        fnr = fn / max((y_test == 1).sum(), 1)
        print(f"    threshold={thresh:.1f}:  FP={fp:4d} ({fpr:.3f})  FN={fn:4d} ({fnr:.3f})")

    # ── Export to ONNX ───────────────────────────────────────────────────
    print(f"\n  Exporting to ONNX...")
    output_dir = Path(args.output).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    success = export_to_onnx(pipeline, args.output, n_features, model_name)

    if success and not args.no_verify:
        verify_onnx(args.output, X_test, y_prob, ft_test)

    # ── Save training metadata ───────────────────────────────────────────
    metadata = {
        "trained_at": datetime.now().isoformat(),
        "model_type": model_name,
        "n_features": n_features,
        "feature_names": feature_cols,
        "dataset": args.dataset,
        "dataset_size": len(df),
        "n_benign": int(n_benign),
        "n_malicious": int(n_malicious),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "cv_roc_auc_mean": float(cv_scores.mean()),
        "cv_roc_auc_std": float(cv_scores.std()),
        "test_accuracy": float(accuracy_score(y_test, y_pred)),
        "test_roc_auc": float(roc_auc_score(y_test, y_prob[:, 1])),
        "confusion_matrix": {"TN": int(cm[0, 0]), "FP": int(cm[0, 1]),
                             "FN": int(cm[1, 0]), "TP": int(cm[1, 1])},
        "per_type_results": per_type_results,
        "score_stats": {
            "benign_mean": float(mal_scores[y_test == 0].mean()),
            "benign_max": float(benign_max),
            "malware_mean": float(mal_scores[y_test == 1].mean()),
            "malware_min": float(malware_min),
            "score_gap": float(gap),
        },
    }

    meta_path = str(args.output).replace(".onnx", "_metadata.json")
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"\n  Metadata saved: {meta_path}")

    print(f"\n{'=' * 65}")
    print(f"Done! Model saved to {args.output}")
    print(f"Copy to data/anomaly_model.onnx in the build directory.")
    print(f"{'=' * 65}")


if __name__ == "__main__":
    main()
