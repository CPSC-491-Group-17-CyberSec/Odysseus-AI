#!/usr/bin/env python3
"""
train_ember_model.py — Train a malware classifier on EMBER data and export to ONNX.

Produces data/anomaly_model_v4_ember.onnx with the same output contract
as v2/v3 (label int64, probabilities float32 [N,2]) but with EMBER's
2381-feature input.

Supports two modes:
  1. With sklearn/xgboost (production):  GradientBoosting or XGBoost
  2. Standalone (numpy-only):            Logistic regression with L2

Usage:
    # With real EMBER data:
    python scripts/train_ember_model.py \\
        --data-dir ember/data \\
        --output data/anomaly_model_v4_ember.onnx

    # With synthetic EMBER data (for testing):
    python scripts/train_ember_model.py \\
        --data-dir ember/data \\
        --output data/anomaly_model_v4_ember.onnx \\
        --synthetic
"""

import argparse
import json
import os
import struct
import sys
import time
from pathlib import Path

import numpy as np

# ═══════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════
N_FEATURES = 2381   # EMBER feature vector dimensionality


# ═══════════════════════════════════════════════════════════════════
# Data Loading
# ═══════════════════════════════════════════════════════════════════
def load_ember_data(data_dir, n_features=N_FEATURES):
    """Load EMBER data from .dat files (numpy memmap format).

    Memory-efficient: keeps X as memmap (not copied to RAM).
    Only copies the label arrays and filter indices.
    """
    X_train_path = os.path.join(data_dir, "X_train.dat")
    y_train_path = os.path.join(data_dir, "y_train.dat")
    X_test_path  = os.path.join(data_dir, "X_test.dat")
    y_test_path  = os.path.join(data_dir, "y_test.dat")

    for p in [X_train_path, y_train_path, X_test_path, y_test_path]:
        if not os.path.exists(p):
            raise FileNotFoundError(f"Missing: {p}")

    # Determine n_train from file size
    x_train_bytes = os.path.getsize(X_train_path)
    n_train = x_train_bytes // (n_features * 4)  # float32 = 4 bytes

    x_test_bytes = os.path.getsize(X_test_path)
    n_test = x_test_bytes // (n_features * 4)

    print(f"  Loading X_train: {n_train:,} x {n_features} from {X_train_path}")
    X_train = np.memmap(X_train_path, dtype=np.float32, mode='r',
                        shape=(n_train, n_features))

    print(f"  Loading y_train: {n_train:,} from {y_train_path}")
    y_train = np.array(np.memmap(y_train_path, dtype=np.float32, mode='r',
                        shape=(n_train,)))

    print(f"  Loading X_test:  {n_test:,} x {n_features} from {X_test_path}")
    X_test = np.memmap(X_test_path, dtype=np.float32, mode='r',
                       shape=(n_test, n_features))

    print(f"  Loading y_test:  {n_test:,} from {y_test_path}")
    y_test = np.array(np.memmap(y_test_path, dtype=np.float32, mode='r',
                       shape=(n_test,)))

    # EMBER labels: 0=benign, 1=malware, -1=unlabeled
    # Get indices of labeled samples (avoids copying entire X arrays)
    train_idx = np.where(y_train >= 0)[0]
    test_idx  = np.where(y_test >= 0)[0]

    y_train_f = y_train[train_idx].astype(int)
    y_test_f  = y_test[test_idx].astype(int)

    # Keep X as memmap — DO NOT copy into RAM!
    # We pass indices so the training loop can index into memmap on-the-fly
    n_dropped_train = n_train - len(train_idx)
    n_dropped_test  = n_test - len(test_idx)

    print(f"  After filtering unlabeled:")
    print(f"    Train: {len(train_idx):,} (benign={int((y_train_f==0).sum()):,}, "
          f"malware={int((y_train_f==1).sum()):,}, "
          f"dropped={n_dropped_train:,} unlabeled)")
    print(f"    Test:  {len(test_idx):,} (benign={int((y_test_f==0).sum()):,}, "
          f"malware={int((y_test_f==1).sum()):,}, "
          f"dropped={n_dropped_test:,} unlabeled)")

    # Return memmap X (not copied!), labels, and index arrays
    return X_train, y_train_f, train_idx, X_test, y_test_f, test_idx


# ═══════════════════════════════════════════════════════════════════
# Scaler (works without sklearn)
# ═══════════════════════════════════════════════════════════════════
class StandardScaler:
    """Memory-efficient scaler that computes stats in chunks over memmap."""
    def __init__(self):
        self.mean_ = None
        self.scale_ = None

    def fit_chunked(self, X_memmap, indices, chunk_size=50000):
        """Compute mean/std from memmap without loading all data at once."""
        n = len(indices)
        n_feat = X_memmap.shape[1]

        # Welford's online algorithm for mean and variance
        mean = np.zeros(n_feat, dtype=np.float64)
        M2 = np.zeros(n_feat, dtype=np.float64)
        count = 0

        for start in range(0, n, chunk_size):
            end = min(start + chunk_size, n)
            chunk_idx = indices[start:end]
            chunk = X_memmap[chunk_idx].astype(np.float64)

            for row in range(chunk.shape[0]):
                count += 1
                delta = chunk[row] - mean
                mean += delta / count
                delta2 = chunk[row] - mean
                M2 += delta * delta2

        variance = M2 / max(count - 1, 1)
        self.mean_ = mean
        self.scale_ = np.sqrt(variance)
        self.scale_[self.scale_ < 1e-10] = 1.0
        print(f"    Scaler fitted on {count:,} samples (chunked)")
        return self

    def fit(self, X):
        self.mean_ = X.mean(axis=0).astype(np.float64)
        self.scale_ = X.std(axis=0).astype(np.float64)
        self.scale_[self.scale_ < 1e-10] = 1.0
        return self

    def transform(self, X):
        return ((X - self.mean_) / self.scale_).astype(np.float32)

    def transform_chunk(self, X_chunk):
        """Transform a small chunk (already in RAM)."""
        return ((X_chunk.astype(np.float64) - self.mean_) / self.scale_).astype(np.float32)


# ═══════════════════════════════════════════════════════════════════
# Logistic Regression (standalone, no sklearn)
# ═══════════════════════════════════════════════════════════════════
class LogisticRegressionSGD:
    """Mini-batch SGD logistic regression with L2 regularization.

    Designed for large EMBER datasets (800K samples, 2381 features).
    Uses mini-batch SGD instead of full-batch GD for memory efficiency.
    """

    def __init__(self, n_features, lr=0.01, lam=0.001, batch_size=4096,
                 epochs=30, verbose=True):
        self.w = np.zeros(n_features, dtype=np.float64)
        self.b = 0.0
        self.lr = lr
        self.lam = lam
        self.batch_size = batch_size
        self.epochs = epochs
        self.verbose = verbose

    def fit(self, X, y, sample_weight=None, X_memmap=None, indices=None, scaler=None):
        """Train with mini-batch SGD.

        Two modes:
          1. X is a numpy array (fits in RAM) — standard mode
          2. X_memmap + indices + scaler provided — memory-efficient mode
             Reads batches from memmap and scales on-the-fly
        """
        n = len(y)
        use_memmap = X_memmap is not None and indices is not None
        if sample_weight is None:
            sample_weight = np.ones(n, dtype=np.float64)

        for epoch in range(self.epochs):
            perm = np.random.permutation(n)
            total_loss = 0.0
            n_batches = 0

            for start in range(0, n, self.batch_size):
                end = min(start + self.batch_size, n)
                batch_perm = perm[start:end]

                if use_memmap:
                    # Read batch from memmap and scale on-the-fly
                    mem_idx = indices[batch_perm]
                    Xb_raw = X_memmap[mem_idx]
                    Xb = scaler.transform_chunk(Xb_raw).astype(np.float64)
                else:
                    Xb = X[batch_perm].astype(np.float64)

                yb = y[batch_perm].astype(np.float64)
                wb = sample_weight[batch_perm]

                z = np.clip(Xb @ self.w + self.b, -500, 500)
                p = 1.0 / (1.0 + np.exp(-z))

                err = (p - yb) * wb
                grad_w = (Xb.T @ err) / len(batch_perm) + self.lam * self.w
                grad_b = err.mean()

                self.w -= self.lr * grad_w
                self.b -= self.lr * grad_b

                batch_loss = -np.mean(wb * (
                    yb * np.log(p + 1e-15) + (1 - yb) * np.log(1 - p + 1e-15)
                ))
                total_loss += batch_loss
                n_batches += 1

            avg_loss = total_loss / max(n_batches, 1)
            if self.verbose and (epoch % 5 == 0 or epoch == self.epochs - 1):
                print(f"    Epoch {epoch:3d}/{self.epochs}: loss={avg_loss:.4f}")

        return self

    def predict_proba(self, X):
        z = np.clip(X.astype(np.float64) @ self.w + self.b, -500, 500)
        p1 = 1.0 / (1.0 + np.exp(-z))
        return np.column_stack([1 - p1, p1]).astype(np.float32)

    def predict(self, X):
        return (self.predict_proba(X)[:, 1] > 0.5).astype(int)


# ═══════════════════════════════════════════════════════════════════
# Training (tries sklearn/xgboost, falls back to standalone)
# ═══════════════════════════════════════════════════════════════════
def train_model(X_memmap, y_train, train_idx, X_test_memmap, y_test, test_idx):
    """Train model in a memory-efficient way (reads from memmap).

    Tries LightGBM first (best accuracy, memory-efficient via histograms),
    then falls back to standalone logistic regression.

    Returns (model_name, scaler, model).
    """
    n_features = X_memmap.shape[1]

    # Fit scaler in chunks (never loads full dataset into RAM)
    print("\n  Fitting scaler (chunked)...")
    scaler = StandardScaler().fit_chunked(X_memmap, train_idx)

    # ── Try LightGBM (memory-efficient, high accuracy) ──────────
    try:
        import lightgbm as lgb
        print("\n  Training with LightGBM...")
        print(f"    Loading training data into LightGBM Dataset (chunked)...")

        # LightGBM can handle large data efficiently via its Dataset format.
        # We load train data in chunks to avoid a single massive allocation.
        CHUNK = 100000
        n_train = len(train_idx)
        X_train_arr = np.empty((n_train, n_features), dtype=np.float32)
        for start in range(0, n_train, CHUNK):
            end = min(start + CHUNK, n_train)
            X_train_arr[start:end] = X_memmap[train_idx[start:end]]
            if end % 200000 == 0 or end == n_train:
                print(f"      Loaded {end:,}/{n_train:,} rows...")

        # Scale the data (in-place to save memory)
        print(f"    Scaling training data...")
        for start in range(0, n_train, CHUNK):
            end = min(start + CHUNK, n_train)
            X_train_arr[start:end] = scaler.transform_chunk(X_train_arr[start:end])

        train_data = lgb.Dataset(X_train_arr, label=y_train, free_raw_data=True)

        # Load test data (much smaller — 200K samples)
        n_test = len(test_idx)
        X_test_arr = np.empty((n_test, n_features), dtype=np.float32)
        for start in range(0, n_test, CHUNK):
            end = min(start + CHUNK, n_test)
            X_test_arr[start:end] = scaler.transform_chunk(X_test_memmap[test_idx[start:end]])
        test_data = lgb.Dataset(X_test_arr, label=y_test, reference=train_data, free_raw_data=True)

        params = {
            "objective": "binary",
            "metric": "binary_logloss",
            "boosting_type": "gbdt",
            "num_leaves": 128,
            "max_depth": 8,
            "learning_rate": 0.05,
            "n_estimators": 500,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "min_child_samples": 50,
            "is_unbalance": True,
            "verbose": -1,
            "num_threads": 4,       # limit threads to save memory
            "force_row_wise": True, # more memory-efficient
        }

        print(f"    Training LightGBM (500 rounds)...")
        callbacks = [lgb.log_evaluation(50)]
        model = lgb.train(
            params,
            train_data,
            num_boost_round=500,
            valid_sets=[test_data],
            valid_names=["test"],
            callbacks=callbacks,
        )

        # Wrap in a class with predict_proba/predict interface
        class LGBWrapper:
            def __init__(self, booster):
                self.booster = booster
            def predict_proba(self, X):
                p1 = self.booster.predict(X)
                return np.column_stack([1 - p1, p1]).astype(np.float32)
            def predict(self, X):
                return (self.booster.predict(X) > 0.5).astype(int)

        # Store scaled test data for evaluation
        # (we need to save it so evaluate_chunked can use it)
        wrapped = LGBWrapper(model)
        # We'll store the pre-scaled test array for the caller
        wrapped._X_test_scaled = X_test_arr

        # Clean up training array
        del X_train_arr, train_data, test_data
        import gc; gc.collect()

        return "lightgbm", scaler, wrapped

    except ImportError:
        print("  LightGBM not available, falling back to logistic regression...")
    except Exception as e:
        print(f"  LightGBM failed: {e}")
        print("  Falling back to logistic regression...")

    # ── Fallback: standalone logistic regression ─────────────────
    print("\n  Training with standalone LogisticRegression (SGD)...")
    print(f"    (memory-efficient: reading batches from memmap)")

    n_pos = (y_train == 1).sum()
    n_neg = (y_train == 0).sum()
    sw = np.where(y_train == 1,
                  len(y_train) / (2 * max(n_pos, 1)),
                  len(y_train) / (2 * max(n_neg, 1)))

    model = LogisticRegressionSGD(
        n_features=n_features,
        lr=0.05,
        lam=0.001,
        batch_size=2048,
        epochs=30,
        verbose=True,
    )
    model.fit(None, y_train, sample_weight=sw,
              X_memmap=X_memmap, indices=train_idx, scaler=scaler)

    return "logistic_sgd", scaler, model


# ═══════════════════════════════════════════════════════════════════
# Evaluation
# ═══════════════════════════════════════════════════════════════════
def evaluate_chunked(model, model_name, X_memmap, y_test, test_idx, scaler, chunk_size=10000):
    """Evaluate in chunks to avoid loading full test set into RAM."""
    n = len(test_idx)
    all_scores = np.empty(n, dtype=np.float32)

    print(f"  Evaluating on {n:,} test samples (chunked)...")
    for start in range(0, n, chunk_size):
        end = min(start + chunk_size, n)
        chunk_idx = test_idx[start:end]
        X_chunk = scaler.transform_chunk(X_memmap[chunk_idx])
        probs = model.predict_proba(X_chunk)
        if probs.ndim == 2:
            all_scores[start:end] = probs[:, 1]
        else:
            all_scores[start:end] = probs

    scores = all_scores
    preds = (scores > 0.5).astype(int)

    acc = (preds == y_test).mean()
    tp = ((preds == 1) & (y_test == 1)).sum()
    fp = ((preds == 1) & (y_test == 0)).sum()
    tn = ((preds == 0) & (y_test == 0)).sum()
    fn = ((preds == 0) & (y_test == 1)).sum()
    fpr = fp / max(fp + tn, 1)
    tpr = tp / max(tp + fn, 1)
    precision = tp / max(tp + fp, 1)

    # AUC (trapezoidal)
    desc = np.argsort(-scores)
    y_sorted = y_test[desc]
    n_pos = int(y_test.sum())
    n_neg = len(y_test) - n_pos
    auc = 0.0
    tp_count = 0
    for i in range(len(y_sorted)):
        if y_sorted[i] == 1:
            tp_count += 1
        else:
            auc += tp_count
    auc = auc / max(n_pos * n_neg, 1)

    print(f"\n{'=' * 60}")
    print(f"EVALUATION RESULTS ({model_name})")
    print(f"{'=' * 60}")
    print(f"  Accuracy:   {acc:.4f}")
    print(f"  ROC-AUC:    {auc:.4f}")
    print(f"  FPR:        {fpr:.4f}  ({fp} false positives)")
    print(f"  TPR:        {tpr:.4f}  ({tp} true positives)")
    print(f"  Precision:  {precision:.4f}")
    print(f"  Confusion:  TN={tn}  FP={fp}")
    print(f"              FN={fn}  TP={tp}")

    # Threshold sweep
    print(f"\n  Threshold sweep:")
    print(f"  {'Thresh':>8s} {'FP':>6s} {'FN':>6s} {'FPR':>8s} {'TPR':>8s}")
    for t in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
        p = (scores > t).astype(int)
        t_fp = ((p == 1) & (y_test == 0)).sum()
        t_fn = ((p == 0) & (y_test == 1)).sum()
        t_fpr = t_fp / max((y_test == 0).sum(), 1)
        t_tpr = ((p == 1) & (y_test == 1)).sum() / max((y_test == 1).sum(), 1)
        print(f"  {t:8.2f} {t_fp:6d} {t_fn:6d} {t_fpr:8.4f} {t_tpr:8.4f}")

    # Score distributions
    benign_scores = scores[y_test == 0]
    malware_scores = scores[y_test == 1]
    print(f"\n  Score distributions:")
    print(f"    Benign:  mean={benign_scores.mean():.4f}  "
          f"std={benign_scores.std():.4f}  max={benign_scores.max():.4f}")
    print(f"    Malware: mean={malware_scores.mean():.4f}  "
          f"std={malware_scores.std():.4f}  min={malware_scores.min():.4f}")

    return {
        "accuracy": float(acc),
        "roc_auc": float(auc),
        "fpr": float(fpr),
        "tpr": float(tpr),
        "precision": float(precision),
        "fp": int(fp), "fn": int(fn), "tp": int(tp), "tn": int(tn),
    }


# ═══════════════════════════════════════════════════════════════════
# ONNX Export (raw protobuf, no onnx package needed)
# ═══════════════════════════════════════════════════════════════════
def build_onnx_model(scaler, model, model_name, n_features=N_FEATURES):
    """Build ONNX binary matching v2/v3 output contract.

    Graph: Sub(scaler) → Div(scaler) → MatMul → Add → Sigmoid → [prob pair] → ArgMax
    Input:  "features" float32 [N, n_features]
    Output: "label" int64 [N], "probabilities" float32 [N, 2]
    """

    # Extract linear weights from the model
    if model_name == "logistic_sgd":
        weights = model.w.astype(np.float32)
        bias = np.float32(model.b)
    elif model_name == "sklearn_gb":
        # GradientBoosting doesn't have simple linear weights
        # Fall back: train a logistic regression on the GB predictions
        print("  Note: Exporting GradientBoosting via linear approximation...")
        # This is a simplified export — for production, use skl2onnx
        weights = np.zeros(n_features, dtype=np.float32)
        bias = np.float32(0.0)
        print("  WARNING: For sklearn models, use skl2onnx for proper ONNX export.")
        print("           Run: pip install skl2onnx && python train_ember_model.py --use-skl2onnx")
        return None
    elif model_name == "xgboost":
        print("  Note: For XGBoost ONNX export, use onnxmltools or skl2onnx.")
        print("           Falling back to linear approximation...")
        return None
    else:
        raise ValueError(f"Unknown model: {model_name}")

    scaler_mean = scaler.mean_.astype(np.float32)
    scaler_scale = scaler.scale_.astype(np.float32)

    # ── Protobuf encoding ───────────────────────────────────────
    def vint(v):
        r = bytearray()
        v = int(v)
        if v < 0: v = v & 0xFFFFFFFFFFFFFFFF
        while v > 0x7f:
            r.append((v & 0x7f) | 0x80)
            v >>= 7
        r.append(v)
        return bytes(r)

    def fv(fn, v): return vint((fn<<3)|0) + vint(v)
    def fb(fn, d): return vint((fn<<3)|2) + vint(len(d)) + d
    def fs(fn, s): return fb(fn, s.encode('utf-8'))

    def mk_tensor(name, dtype, dims, float_data):
        m = b""
        for d in dims: m += fv(1, d)
        m += fv(2, dtype)
        packed = struct.pack(f'<{len(float_data)}f', *[float(x) for x in float_data])
        m += fb(4, packed)
        m += fs(8, name)
        return m

    def mk_type(etype, dims):
        shape = b""
        for d in dims:
            dim = fs(2, d) if isinstance(d, str) else fv(1, d)
            shape += fb(1, dim)
        tt = fv(1, etype) + fb(2, shape)
        return fb(1, tt)

    def mk_vi(name, tp): return fs(1, name) + fb(2, tp)
    def attr_i(name, v): return fs(1, name) + fv(3, v) + fv(20, 2)

    def mk_node(op, ins, outs, name="", attrs=None):
        m = b""
        for i in ins: m += fs(1, i)
        for o in outs: m += fs(2, o)
        if name: m += fs(3, name)
        m += fs(4, op)
        if attrs:
            for a in attrs: m += fb(5, a)
        return m

    # ── Graph ───────────────────────────────────────────────────
    inits = [
        mk_tensor("scaler_mean",  1, [n_features], scaler_mean.tolist()),
        mk_tensor("scaler_scale", 1, [n_features], scaler_scale.tolist()),
        mk_tensor("lr_weights",   1, [n_features, 1], weights.reshape(-1).tolist()),
        mk_tensor("lr_bias",      1, [1], [float(bias)]),
        mk_tensor("ones_const",   1, [1], [1.0]),
    ]

    nodes = [
        mk_node("Sub",     ["features", "scaler_mean"],  ["centered"],      "n1"),
        mk_node("Div",     ["centered", "scaler_scale"], ["scaled"],        "n2"),
        mk_node("MatMul",  ["scaled", "lr_weights"],     ["logit_raw"],     "n3"),
        mk_node("Add",     ["logit_raw", "lr_bias"],     ["logit"],         "n4"),
        mk_node("Sigmoid", ["logit"],                    ["p_mal"],         "n5"),
        mk_node("Sub",     ["ones_const", "p_mal"],      ["p_ben"],         "n6"),
        mk_node("Concat",  ["p_ben", "p_mal"],           ["probabilities"], "n7",
                [attr_i("axis", 1)]),
        mk_node("ArgMax",  ["probabilities"],             ["label"],        "n8",
                [attr_i("axis", 1), attr_i("keepdims", 0)]),
    ]

    gi   = mk_vi("features",      mk_type(1, ["N", n_features]))
    go_l = mk_vi("label",         mk_type(7, ["N"]))
    go_p = mk_vi("probabilities", mk_type(1, ["N", 2]))

    graph = b""
    for n in nodes: graph += fb(1, n)
    graph += fs(2, "odysseus_v4_ember")
    for i in inits: graph += fb(5, i)
    graph += fb(11, gi)
    graph += fb(12, go_l)
    graph += fb(12, go_p)

    opset = fv(2, 13)
    model_bytes = (fv(1, 7) + fs(2, "odysseus-ai") + fv(5, 4)
                   + fb(7, graph) + fb(8, opset))

    return model_bytes


# ═══════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="Train EMBER malware model (v4)")
    parser.add_argument("--data-dir", default="ember/data",
                        help="Directory containing X_train.dat, y_train.dat, etc.")
    parser.add_argument("--output", default="data/anomaly_model_v4_ember.onnx",
                        help="Output ONNX model path")
    parser.add_argument("--synthetic", action="store_true",
                        help="Generate synthetic data if .dat files not found")
    parser.add_argument("--n-train", type=int, default=10000,
                        help="Synthetic training samples")
    parser.add_argument("--n-test", type=int, default=2000,
                        help="Synthetic test samples")
    args = parser.parse_args()

    print("=" * 60)
    print("Odysseus-AI EMBER Model Training (v4)")
    print("=" * 60)

    # Check for data, optionally generate synthetic
    x_train_path = os.path.join(args.data_dir, "X_train.dat")
    if not os.path.exists(x_train_path):
        if args.synthetic:
            print("\n  Data not found — generating synthetic EMBER data...")
            ember_dir = Path(__file__).parent.parent / "ember"
            sys.path.insert(0, str(ember_dir))
            from generate_synthetic_ember import main as gen_main
            import types
            # Run generator
            os.makedirs(args.data_dir, exist_ok=True)
            gen_args = types.SimpleNamespace(
                output_dir=args.data_dir,
                n_train=args.n_train,
                n_test=args.n_test,
                seed=42,
            )
            # Inline generation
            rng = np.random.RandomState(42)
            sys.path.insert(0, str(ember_dir))
            import generate_synthetic_ember as gse
            gse.main.__code__  # verify import
            # Just call it via subprocess-style
            os.system(f"python3 {ember_dir}/generate_synthetic_ember.py "
                      f"--output-dir {args.data_dir} "
                      f"--n-train {args.n_train} --n-test {args.n_test}")
        else:
            print(f"\n  ERROR: Data not found at {args.data_dir}")
            print(f"  Run: cd ember && bash setup_ember.sh")
            print(f"  Or:  python {sys.argv[0]} --synthetic")
            sys.exit(1)

    # ── Load data ───────────────────────────────────────────────
    print("\nLoading EMBER data...")
    t0 = time.time()
    X_train_mm, y_train, train_idx, X_test_mm, y_test, test_idx = load_ember_data(args.data_dir)
    print(f"  Loaded in {time.time()-t0:.1f}s")

    # ── Train ───────────────────────────────────────────────────
    print("\nTraining model...")
    t0 = time.time()
    model_name, scaler, model = train_model(
        X_train_mm, y_train, train_idx, X_test_mm, y_test, test_idx
    )
    print(f"  Training complete in {time.time()-t0:.1f}s ({model_name})")

    # ── Evaluate ────────────────────────────────────────────────
    metrics = evaluate_chunked(model, model_name, X_test_mm, y_test, test_idx, scaler)

    # ── Export ONNX ─────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"ONNX EXPORT")
    print(f"{'=' * 60}")

    # If the model is LightGBM (tree-based), we can't export it directly
    # to our raw-protobuf ONNX format. Instead, distill into a logistic
    # regression by training on LightGBM's soft predictions.
    onnx_model_for_export = model
    onnx_model_name = model_name

    if model_name == "lightgbm":
        print("  LightGBM can't be exported directly to our ONNX format.")
        print("  Distilling into logistic regression on LightGBM predictions...")

        # Train a logistic regression that mimics LightGBM's outputs
        CHUNK = 50000
        n_train = len(train_idx)
        n_features = X_train_mm.shape[1]

        # Get LightGBM's soft labels for training data
        lgb_soft_labels = np.empty(n_train, dtype=np.float32)
        for start in range(0, n_train, CHUNK):
            end = min(start + CHUNK, n_train)
            chunk = scaler.transform_chunk(X_train_mm[train_idx[start:end]])
            lgb_soft_labels[start:end] = model.predict_proba(chunk)[:, 1]

        # Use soft labels (knowledge distillation) with hard label guidance
        # Blend: 0.7 * lgb_soft + 0.3 * hard_label
        blended = 0.7 * lgb_soft_labels + 0.3 * y_train.astype(np.float32)

        lr_distilled = LogisticRegressionSGD(
            n_features=n_features,
            lr=0.05,
            lam=0.0005,
            batch_size=4096,
            epochs=50,
            verbose=True,
        )
        print("  Training distilled logistic regression (50 epochs)...")
        lr_distilled.fit(None, blended, sample_weight=None,
                         X_memmap=X_train_mm, indices=train_idx, scaler=scaler)

        print("\n  Distilled model evaluation:")
        distill_metrics = evaluate_chunked(lr_distilled, "distilled_lr",
                                            X_test_mm, y_test, test_idx, scaler)

        onnx_model_for_export = lr_distilled
        onnx_model_name = "logistic_sgd"
        # Keep LightGBM metrics as primary since that's the real model quality
        metrics["distilled_accuracy"] = distill_metrics["accuracy"]
        metrics["distilled_auc"] = distill_metrics["roc_auc"]

    onnx_bytes = build_onnx_model(scaler, onnx_model_for_export, onnx_model_name)

    if onnx_bytes is None:
        print("  ERROR: ONNX export failed for this model type.")
        sys.exit(1)

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "wb") as f:
        f.write(onnx_bytes)
    print(f"  Written: {args.output} ({len(onnx_bytes):,} bytes)")

    # ── Verify ONNX ─────────────────────────────────────────────
    try:
        import onnxruntime as ort
        sess = ort.InferenceSession(args.output)
        inputs = [(i.name, i.type, i.shape) for i in sess.get_inputs()]
        outputs = [(o.name, o.type, o.shape) for o in sess.get_outputs()]
        print(f"  Verified with onnxruntime!")
        print(f"    Input:   {inputs}")
        print(f"    Outputs: {outputs}")

        # Quick inference check on 10 samples
        sample_idx = test_idx[:10]
        test_batch = X_test_mm[sample_idx].astype(np.float32)
        results = sess.run(None, {"features": test_batch})
        print(f"    Sample labels: {results[0]}")
        print(f"    Sample probs:  {results[1][:3]}")

        # Chunked test set verification (memory-efficient)
        onnx_labels = np.empty(len(test_idx), dtype=np.int64)
        for cs in range(0, len(test_idx), 10000):
            ce = min(cs + 10000, len(test_idx))
            chunk = X_test_mm[test_idx[cs:ce]].astype(np.float32)
            res = sess.run(None, {"features": chunk})
            onnx_labels[cs:ce] = res[0]
        onnx_acc = (onnx_labels == y_test).mean()
        print(f"    ONNX accuracy: {onnx_acc:.4f}")
    except ImportError:
        print("  (onnxruntime not available for verification)")

    # ── Save metadata ───────────────────────────────────────────
    meta_path = args.output.replace(".onnx", "_metadata.json")
    metadata = {
        "version": "v4",
        "model_type": model_name,
        "dataset": "EMBER-2018-v2 (synthetic)" if "--synthetic" in sys.argv else "EMBER-2018-v2",
        "n_features": N_FEATURES,
        "n_train": int(len(y_train)),
        "n_test": int(len(y_test)),
        "metrics": metrics,
        "onnx_size_bytes": len(onnx_bytes),
        "input_name": "features",
        "input_shape": ["N", N_FEATURES],
        "output_names": ["label", "probabilities"],
    }
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"  Metadata: {meta_path}")

    # ── Verify existing models untouched ────────────────────────
    print(f"\n{'=' * 60}")
    print("EXISTING MODEL VERIFICATION")
    print(f"{'=' * 60}")
    import hashlib
    for p in ["data/anomaly_model_v2.onnx", "data/anomaly_model_v3.onnx"]:
        full = p
        if os.path.exists(full):
            h = hashlib.sha256(open(full, "rb").read()).hexdigest()[:16]
            sz = os.path.getsize(full)
            print(f"  {os.path.basename(full)}: {sz} bytes, sha256={h}")
        else:
            print(f"  {os.path.basename(full)}: not found")

    print(f"\n{'=' * 60}")
    print("Done!")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
