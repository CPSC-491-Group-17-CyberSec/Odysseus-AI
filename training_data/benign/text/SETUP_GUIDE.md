# Odysseus-AI: Setup & Usage Guide

## Overview

Odysseus-AI is a cross-platform antivirus scanner built with C++17 and Qt6. It uses a two-pass detection pipeline:

1. **Hash-based detection** — compares file SHA-256 hashes against a known malware database (fast, catches known threats)
2. **AI anomaly detection** — extracts 38 numerical features from each file and feeds them into a machine learning model (XGBoost via ONNX Runtime) to catch unknown/zero-day threats
3. **LLM threat explanation** — when a file is flagged, a locally running LLM (Llama 3 via Ollama) generates a plain-English explanation of why the file is suspicious and what to do next

---

## Prerequisites

Before building, make sure you have the following installed:

- **macOS** (Apple Silicon or Intel)
- **Homebrew** — https://brew.sh
- **CMake** (3.20+)
- **Qt6** (with Widgets and Network modules)
- **ONNX Runtime** (for AI anomaly detection)
- **Ollama** (for LLM threat explanations)
- **Python 3** (for training pipeline only)

---

## Step 1: Install Dependencies

Open Terminal and run:

```bash
# Install build tools
brew install cmake qt@6

# Install ONNX Runtime (required for AI anomaly detection)
brew install onnxruntime

# Install OpenMP (required by XGBoost for model training)
brew install libomp

# Install Ollama (required for LLM threat explanations)
brew install ollama
```

---

## Step 2: Clone the Repository

```bash
git clone https://github.com/CPSC-491-Group-17-CyberSec/Odysseus-AI.git
cd Odysseus-AI
```

Make sure you're on the correct branch:

```bash
git checkout feature/oai-22-ai-detection
```

---

## Step 3: Build the Project

```bash
mkdir -p build
cd build
cmake .. -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

You should see these messages during configuration:

```
-- ONNX Runtime found – AI anomaly detection enabled
-- Configuring done
-- Generating done
```

If you see "ONNX Runtime NOT found", the scanner will still build and work — it just runs in hash-only mode without AI detection. Make sure onnxruntime is installed via brew.

The build finishes with:

```
[100%] Built target main
```

---

## Step 4: Set Up Ollama (LLM Explanations)

Ollama runs a local LLM on your machine — no API keys or internet needed for inference.

```bash
# Start Ollama (may already be running as a background service after brew install)
ollama serve
```

If you see `Error: listen tcp 127.0.0.1:11434: bind: address already in use`, that means Ollama is already running in the background. This is fine — skip to the next command.

```bash
# Pull the Llama 3 model (~4.7 GB download, one-time only)
ollama pull llama3
```

Wait for it to finish (you'll see "success" when done).

To verify Ollama is working:

```bash
ollama list
```

You should see `llama3` in the output.

---

## Step 5: Run the Scanner

From the build directory:

```bash
./main
```

This launches the Odysseus-AI Qt dashboard. When you start a scan:

1. Files are enumerated from the selected directory
2. Each file goes through hash-based detection first (fast path)
3. If no hash match, the AI anomaly model scores the file (38-feature extraction + XGBoost inference)
4. If the AI flags a file (score > 0.5), Ollama generates a plain-English explanation
5. Flagged files appear in the dashboard with their category, reason, and AI analysis

Console output will confirm what's loaded:

```
[FileScannerDetectors] AI model loaded from .../data/anomaly_model.onnx
[FileScannerDetectors] Ollama is running – LLM threat explanations enabled (model: llama3)
```

If Ollama is not running, you'll see:

```
[FileScannerDetectors] Ollama not reachable – LLM explanations disabled.
```

The scanner still works fine without Ollama — you just won't get the English explanations.

---

## Step 6: Train the Model (Optional)

The repository includes a pre-trained model (`data/anomaly_model.onnx`) trained on synthetic data. To retrain with real samples:

### Install Python dependencies

```bash
pip3 install scikit-learn xgboost skl2onnx onnxmltools onnxruntime numpy pandas
```

If XGBoost fails to load, install OpenMP:

```bash
brew install libomp
```

### Generate training data from real files

```bash
python3 scripts/generate_dataset.py \
    --malware-dir /path/to/malware/samples \
    --benign-dir /path/to/benign/files \
    --output data/dataset.csv
```

Or use the synthetic data generator:

```bash
python3 scripts/generate_synthetic_dataset.py
```

### Train and export the model

```bash
python3 scripts/train_model.py
```

This trains an XGBoost classifier, runs 5-fold cross-validation, prints a classification report, and exports the model to `data/anomaly_model.onnx`.

### Run feature extractor tests

```bash
python3 scripts/test_feature_extractor.py
```

All tests should pass.

---

## Project Structure

```
Odysseus-AI/
├── include/ai/
│   ├── FeatureExtractor.h      # 38-feature vector API
│   ├── AnomalyDetector.h       # ONNX Runtime inference wrapper
│   └── LLMExplainer.h          # Ollama LLM integration
├── src/ai/
│   ├── FeatureExtractor.cpp    # Feature extraction (4 passes)
│   ├── AnomalyDetector.cpp     # ML model scoring
│   └── LLMExplainer.cpp        # LLM threat explanation
├── src/core/
│   ├── FileScanner.h           # Scanner API + data structures
│   ├── FileScannerHash.cpp     # Hash-based detection + worker
│   ├── FileScannerDetectors.cpp# AI detection + LLM integration
│   ├── FileScannerEngine.cpp   # Scan loop controller
│   └── FileScannerContext.cpp  # OS/FS detection
├── scripts/
│   ├── generate_dataset.py     # Real-file feature extraction
│   ├── generate_synthetic_dataset.py  # Synthetic training data
│   ├── train_model.py          # Model training + ONNX export
│   └── test_feature_extractor.py     # Unit tests
├── data/
│   ├── anomaly_model.onnx      # Trained ML model
│   ├── dataset.csv             # Training dataset
│   └── malware_hashes.txt      # Known malware hash database
├── docs/
│   ├── AI_ANOMALY_DETECTION.md # Technical documentation
│   └── SETUP_GUIDE.md          # This file
└── CMakeLists.txt              # Build configuration
```

---

## How the AI Detection Works

### Feature Extraction (38 features)

The scanner extracts 38 numerical features from each file, grouped into 4 passes:

**Pass 1 — Metadata & Entropy (features 0-4):** File size, Shannon entropy, file type flags (executable, script, DLL)

**Pass 2 — Byte Distribution (features 5-15):** Null byte ratio, printable ASCII ratio, high byte ratio, byte mean/stddev, control characters, whitespace, unique byte count, longest null run, quarter entropies

**Pass 3 — PE Header Analysis (features 16-27):** For Windows executables: section count, max section entropy, code section ratio, entry point validation, debug info, import/export counts, resource ratio, section name anomalies, timestamp anomalies, virtual-to-raw size ratio

**Pass 4 — String Analysis (features 28-37):** String count, density, average/max length, suspicious API call count (32 known malware APIs), URL count, IP address count, registry path count, base64 string count, hash partial match

### ML Model

XGBoost Gradient Boosted Tree classifier trained on labeled benign/malicious samples. Exported to ONNX format for fast C++ inference via ONNX Runtime. Outputs a probability score from 0.0 to 1.0 — files scoring above 0.5 are flagged.

### LLM Explanation

When a file is flagged, the 38 features + anomaly score are formatted into a structured prompt and sent to a locally running Llama 3 model via Ollama. The LLM returns a plain-English explanation covering why the file is suspicious, what the indicators mean, and recommended next steps.

---

## Troubleshooting

**"ONNX Runtime NOT found" during cmake:**
Make sure onnxruntime is installed: `brew install onnxruntime`

**"Error: listen tcp 127.0.0.1:11434: bind: address already in use":**
Ollama is already running as a background service. This is normal — just proceed with `ollama pull llama3`.

**XGBoost import error (libomp not found):**
Install OpenMP: `brew install libomp`

**"onnxmltools" not found during training:**
Install it: `pip3 install onnxmltools`

**Build fails with header not found:**
Make sure you're building from the `build/` directory and ran cmake first.

**Scanner runs but no AI detection:**
Check that `data/anomaly_model.onnx` exists in the build directory (cmake copies the data/ folder automatically).

---

## Team Members

- **Kelvin Cuellar** — AI Training & Anomaly Detection (OAI-22)
- Yazan, Ethan, Alexander — (other assignments)

## Tech Stack

- C++17, Qt6 (Widgets + Network)
- XGBoost / scikit-learn (model training)
- ONNX Runtime (C++ inference)
- Ollama + Llama 3 (local LLM explanations)
- CMake (build system)
- SQLite (scan history persistence)
