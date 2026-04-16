#!/usr/bin/env python3
"""Auto-generated ONNX-compatible scorer for v3 model."""
import numpy as np
import json, os

PARAMS_FILE = os.path.join(os.path.dirname(__file__), "anomaly_model_v3_params.json")

def load_model():
    with open(PARAMS_FILE) as f:
        params = json.load(f)
    return params

def predict(X, params=None):
    if params is None:
        params = load_model()
    mean = np.array(params["scaler_mean"], dtype=np.float32)
    std = np.array(params["scaler_std"], dtype=np.float32)
    w = np.array(params["weights"], dtype=np.float32)
    b = params["bias"]

    scaled = (X - mean) / std
    logit = scaled @ w + b
    prob1 = 1.0 / (1.0 + np.exp(-np.clip(logit, -500, 500)))
    probs = np.column_stack([1 - prob1, prob1]).astype(np.float32)
    labels = (prob1 > 0.5).astype(np.int64)
    return labels, probs

if __name__ == "__main__":
    import sys
    params = load_model()
    test = np.zeros((1, params["n_features"]), dtype=np.float32)
    labels, probs = predict(test, params)
    print(f"Test prediction: label={labels[0]}, probs={probs[0]}")
