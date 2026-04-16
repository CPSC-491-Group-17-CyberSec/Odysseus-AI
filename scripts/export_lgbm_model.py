#!/usr/bin/env python3
"""
export_lgbm_model.py — Export the trained LightGBM EMBER model to native format.

Retrains the LightGBM model (same params as train_ember_model.py) and saves:
  1. data/ember_lgbm_model.txt  — LightGBM native text format (for C API)
  2. data/ember_scaler.bin      — Scaler mean/scale as raw float64 arrays

The C++ scanner loads these directly via the LightGBM C API, bypassing
the ONNX distillation and getting the full 96.5% accuracy.

Usage:
    cd ~/Odysseus-AI
    source ember/venv/bin/activate
    python3 scripts/export_lgbm_model.py
"""

import os
import sys
import time
import struct
import numpy as np

# ── Constants ────────────────────────────────────────────────────────────────
N_FEATURES = 2381
DATA_DIR = "ember/data"
OUTPUT_MODEL = "data/ember_lgbm_model.txt"
OUTPUT_SCALER = "data/ember_scaler.bin"

# ── Load EMBER data ──────────────────────────────────────────────────────────
print("=" * 60)
print("Export LightGBM EMBER Model for C++ Scanner")
print("=" * 60)

print("\nLoading EMBER data...")
t0 = time.time()

X_train_path = os.path.join(DATA_DIR, "X_train.dat")
y_train_path = os.path.join(DATA_DIR, "y_train.dat")
X_test_path  = os.path.join(DATA_DIR, "X_test.dat")
y_test_path  = os.path.join(DATA_DIR, "y_test.dat")

for p in [X_train_path, y_train_path, X_test_path, y_test_path]:
    if not os.path.exists(p):
        print(f"  ERROR: Missing {p}")
        print("  Run: cd ember && bash setup_ember.sh")
        sys.exit(1)

x_train_bytes = os.path.getsize(X_train_path)
n_train = x_train_bytes // (N_FEATURES * 4)
x_test_bytes = os.path.getsize(X_test_path)
n_test = x_test_bytes // (N_FEATURES * 4)

X_train_mm = np.memmap(X_train_path, dtype=np.float32, mode='r', shape=(n_train, N_FEATURES))
y_train_all = np.array(np.memmap(y_train_path, dtype=np.float32, mode='r', shape=(n_train,)))
X_test_mm = np.memmap(X_test_path, dtype=np.float32, mode='r', shape=(n_test, N_FEATURES))
y_test_all = np.array(np.memmap(y_test_path, dtype=np.float32, mode='r', shape=(n_test,)))

train_idx = np.where(y_train_all >= 0)[0]
test_idx = np.where(y_test_all >= 0)[0]
y_train = y_train_all[train_idx].astype(int)
y_test = y_test_all[test_idx].astype(int)

print(f"  Train: {len(train_idx):,} samples ({(y_train==0).sum():,} benign, {(y_train==1).sum():,} malware)")
print(f"  Test:  {len(test_idx):,} samples")
print(f"  Loaded in {time.time()-t0:.1f}s")

# ── Compute scaler (chunked) ────────────────────────────────────────────────
print("\nFitting scaler (chunked)...")
CHUNK = 50000
n = len(train_idx)
mean = np.zeros(N_FEATURES, dtype=np.float64)
M2 = np.zeros(N_FEATURES, dtype=np.float64)
count = 0

for start in range(0, n, CHUNK):
    end = min(start + CHUNK, n)
    chunk = X_train_mm[train_idx[start:end]].astype(np.float64)
    for row in range(chunk.shape[0]):
        count += 1
        delta = chunk[row] - mean
        mean += delta / count
        delta2 = chunk[row] - mean
        M2 += delta * delta2

variance = M2 / max(count - 1, 1)
scale = np.sqrt(variance)
scale[scale < 1e-10] = 1.0
print(f"  Scaler fitted on {count:,} samples")

# Save scaler as binary (mean + scale, both float64)
with open(OUTPUT_SCALER, "wb") as f:
    f.write(struct.pack("<I", N_FEATURES))  # feature count
    f.write(mean.tobytes())                  # float64[N_FEATURES]
    f.write(scale.tobytes())                 # float64[N_FEATURES]
print(f"  Saved: {OUTPUT_SCALER} ({os.path.getsize(OUTPUT_SCALER):,} bytes)")

# ── Load & scale data for LightGBM ──────────────────────────────────────────
print("\nLoading training data into memory (chunked)...")
import lightgbm as lgb

n_train_samples = len(train_idx)
X_train_arr = np.empty((n_train_samples, N_FEATURES), dtype=np.float32)
for start in range(0, n_train_samples, CHUNK):
    end = min(start + CHUNK, n_train_samples)
    raw = X_train_mm[train_idx[start:end]].astype(np.float64)
    X_train_arr[start:end] = ((raw - mean) / scale).astype(np.float32)
    if end % 200000 == 0 or end == n_train_samples:
        print(f"  {end:,}/{n_train_samples:,} rows loaded & scaled")

n_test_samples = len(test_idx)
X_test_arr = np.empty((n_test_samples, N_FEATURES), dtype=np.float32)
for start in range(0, n_test_samples, CHUNK):
    end = min(start + CHUNK, n_test_samples)
    raw = X_test_mm[test_idx[start:end]].astype(np.float64)
    X_test_arr[start:end] = ((raw - mean) / scale).astype(np.float32)

# ── Train LightGBM ──────────────────────────────────────────────────────────
print("\nTraining LightGBM...")
train_data = lgb.Dataset(X_train_arr, label=y_train, free_raw_data=True)
test_data = lgb.Dataset(X_test_arr, label=y_test, reference=train_data, free_raw_data=True)

params = {
    "objective": "binary",
    "metric": "binary_logloss",
    "boosting_type": "gbdt",
    "num_leaves": 128,
    "max_depth": 8,
    "learning_rate": 0.05,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "min_child_samples": 50,
    "is_unbalance": True,
    "verbose": -1,
    "num_threads": 4,
    "force_row_wise": True,
}

callbacks = [lgb.log_evaluation(50)]
model = lgb.train(
    params,
    train_data,
    num_boost_round=500,
    valid_sets=[test_data],
    valid_names=["test"],
    callbacks=callbacks,
)

# ── Save LightGBM model ─────────────────────────────────────────────────────
model.save_model(OUTPUT_MODEL)
print(f"\n  Saved: {OUTPUT_MODEL} ({os.path.getsize(OUTPUT_MODEL):,} bytes)")

# ── Evaluate ─────────────────────────────────────────────────────────────────
print("\nEvaluating...")
preds = model.predict(X_test_arr)
labels = (preds > 0.5).astype(int)

acc = (labels == y_test).mean()
tp = ((labels == 1) & (y_test == 1)).sum()
fp = ((labels == 1) & (y_test == 0)).sum()
tn = ((labels == 0) & (y_test == 0)).sum()
fn = ((labels == 0) & (y_test == 1)).sum()
fpr = fp / max(fp + tn, 1)
tpr = tp / max(tp + fn, 1)

print(f"\n  Accuracy:  {acc:.4f}")
print(f"  TPR:       {tpr:.4f}")
print(f"  FPR:       {fpr:.4f}")
print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")

print(f"\n{'=' * 60}")
print("Done! Files for C++ scanner:")
print(f"  Model:  {OUTPUT_MODEL}")
print(f"  Scaler: {OUTPUT_SCALER}")
print(f"{'=' * 60}")
