# OAI-22: AI Training and Anomaly Detection

## Overview

This document describes the AI-based anomaly detection system implemented for
the Odysseus-AI threat intelligence platform. The system adds a second
detection pass to the existing hash-based scanner, using a trained machine
learning model to identify unknown, obfuscated, or zero-day malware that
doesn't appear in the SHA-256 hash database.

## Architecture

```
File on disk
     |
     v
+-------------------+
| FeatureExtractor  |  38-dimensional feature vector
| (4 passes)        |  extracted from raw file bytes
+-------------------+
     |
     v
+-------------------+
| AnomalyDetector   |  ONNX Runtime inference
| (ONNX model)      |  returns score [0.0 - 1.0]
+-------------------+
     |
     v
+-------------------+
| FileScannerHash   |  if score >= threshold (0.5):
| runHashWorker()   |  flag as "AI Anomaly Detection"
+-------------------+
```

### Detection Pipeline

1. **Pass 1 (Hash Lookup)**: Existing `checkByHash()` — fast SHA-256 lookup
   against the `malware_hashes.txt` database.
2. **Pass 2 (AI Scoring)**: New `checkByAI()` — if hash lookup doesn't match,
   extract features and run ML inference. Files scoring above the threshold
   (default 0.5) are flagged as suspicious.

This two-pass design ensures zero-day threats are caught while keeping the
fast path (known malware) as fast as before.

## 38-Feature Vector

Features are grouped into four extraction passes:

### Pass 1: Metadata + Entropy (features 0-4)

| # | Feature | Description |
|---|---------|-------------|
| 0 | fileSize_log10 | Log10 of file size in bytes |
| 1 | shannonEntropy | Shannon entropy (0-8) of full file |
| 2 | isExecutable | 1 if exe/com/scr/pif/msi/elf/bin |
| 3 | isScript | 1 if bat/cmd/ps1/vbs/js/sh/py etc |
| 4 | isDLL | 1 if dll/sys/drv/ocx/so/dylib |

### Pass 2: Byte Distribution (features 5-15)

| # | Feature | Description |
|---|---------|-------------|
| 5 | nullByteRatio | Fraction of 0x00 bytes |
| 6 | printableAsciiRatio | Fraction of bytes in 0x20-0x7E |
| 7 | highByteRatio | Fraction of bytes > 0x7F |
| 8 | byteMean | Mean byte value (normalized 0-1) |
| 9 | byteStdDev | Std deviation of byte values (normalized) |
| 10 | controlCharRatio | Non-whitespace control chars ratio |
| 11 | whitespaceRatio | Space/tab/LF/CR ratio |
| 12 | uniqueByteCount | Distinct byte values / 256 |
| 13 | longestNullRun | Longest null run / file size |
| 14 | entropyFirstQuarter | Shannon entropy of first 25% |
| 15 | entropyLastQuarter | Shannon entropy of last 25% |

### Pass 3: PE Header Analysis (features 16-27)

| # | Feature | Description |
|---|---------|-------------|
| 16 | isPE | 1 if valid MZ+PE signature found |
| 17 | peNumSections | Number of sections / 16 |
| 18 | peMaxSectionEntropy | Highest section entropy / 8 |
| 19 | peCodeSectionRatio | Code section raw size / file size |
| 20 | peEntryPointInCode | 1 if EP falls within code section |
| 21 | peHasDebugInfo | 1 if debug data directory present |
| 22 | peImportCount | Estimated import count / 100 |
| 23 | peExportCount | 1 if export directory present |
| 24 | peResourceRatio | Resource section size / file size |
| 25 | peSectionNameAnomaly | 1 if unknown section name (UPX, etc) |
| 26 | peTimestampAnomaly | 1 if timestamp < 1990 or > 2030 |
| 27 | peVirtualSizeRatio | Max(virtual/raw) per section / 10 |

### Pass 4: String Analysis (features 28-37)

| # | Feature | Description |
|---|---------|-------------|
| 28 | stringCount | Log10 of printable string count |
| 29 | stringDensity | Total string bytes / file size |
| 30 | avgStringLength | Average string length / 100 |
| 31 | maxStringLength | Max string length / 500 |
| 32 | suspiciousStringCount | Malware API keywords / 10 |
| 33 | urlCount | http/https URL count / 5 |
| 34 | ipAddressCount | IP address pattern count / 5 |
| 35 | registryPathCount | HKEY_ / HKLM / HKCU patterns / 5 |
| 36 | base64StringCount | Long base64-like strings / 5 |
| 37 | hashPartialMatch | Reserved for future use |

## Files Created/Modified

### New Files

| File | Purpose |
|------|---------|
| `include/ai/FeatureExtractor.h` | Header: 38-feature vector API |
| `src/ai/FeatureExtractor.cpp` | Implementation: all 4 extraction passes |
| `include/ai/AnomalyDetector.h` | Header: ONNX inference wrapper |
| `src/ai/AnomalyDetector.cpp` | Implementation: model loading + scoring |
| `scripts/generate_dataset.py` | Extract features from real file samples |
| `scripts/generate_synthetic_dataset.py` | Create synthetic training data |
| `scripts/train_model.py` | Train ML model and export to ONNX |
| `scripts/test_feature_extractor.py` | Unit tests for feature extraction |
| `data/dataset.csv` | Pre-generated synthetic dataset (2000 samples) |
| `docs/AI_ANOMALY_DETECTION.md` | This document |

### Modified Files

| File | Changes |
|------|---------|
| `CMakeLists.txt` | Added AI source files, ONNX Runtime linking, include dirs |
| `src/core/FileScanner.h` | Added `checkByAI()` declaration |
| `src/core/FileScannerHash.cpp` | Wired `checkByAI()` as fallback after hash lookup |
| `src/core/FileScannerDetectors.cpp` | Replaced stub with full AI detection implementation |

## How to Train and Deploy

### Step 1: Collect Samples (or use synthetic data)

**Option A – Real samples (recommended for production):**
```bash
# Organize samples into directories
mkdir -p samples/malware samples/benign

# Copy malware samples (e.g., from VirusTotal, MalwareBazaar)
# Copy benign files (e.g., from /usr/bin, C:\Windows\System32)

# Generate features
python scripts/generate_dataset.py \
    --malware-dir samples/malware \
    --benign-dir samples/benign \
    --output data/dataset.csv
```

**Option B – Synthetic data (for testing the pipeline):**
```bash
python scripts/generate_synthetic_dataset.py \
    --output data/dataset.csv \
    --samples 2000
```

### Step 2: Train the Model

```bash
pip install numpy pandas scikit-learn xgboost skl2onnx onnx onnxruntime

python scripts/train_model.py \
    --dataset data/dataset.csv \
    --output data/anomaly_model.onnx
```

This will:
- Train a Gradient Boosted Tree (XGBoost preferred, sklearn fallback)
- Print accuracy, ROC-AUC, confusion matrix, and top features
- Export the model to ONNX format
- Verify the ONNX output matches sklearn predictions

### Step 3: Build with ONNX Runtime

```bash
# Install ONNX Runtime (macOS)
brew install onnxruntime

# Install ONNX Runtime (Ubuntu/Debian)
# Download from https://github.com/microsoft/onnxruntime/releases

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

The CMake build will:
- Automatically detect ONNX Runtime if installed
- If found: enable AI detection
- If not found: compile in hash-only mode (no AI scoring)

### Step 4: Deploy the Model

Place `anomaly_model.onnx` in the `data/` directory next to the binary:
```
build/
  main              (executable)
  data/
    malware_hashes.txt
    anomaly_model.onnx    <-- place here
```

The scanner will automatically load the model on first scan.

## Thread Safety

- `extractFeatures()` is pure (no shared state) — safe from any thread
- `AnomalyDetector::score()` uses per-call ONNX tensors — safe for concurrent use
- `checkByAI()` uses a singleton detector with lazy initialization protected by `QMutex`
- The global detector is initialized once and never modified, so subsequent reads are lock-free

## Performance Considerations

- Feature extraction adds ~1-5ms per file (dominated by I/O)
- ONNX inference adds ~0.1-0.5ms per file (gradient boosted tree is fast)
- Files < 256 bytes or > 100 MB are skipped (insufficient signal / too slow)
- The AI pass only runs when hash lookup doesn't match (most malware is caught by hash first)

## Suspicious String Keywords

The following Windows API names and patterns are flagged as suspicious
(commonly used in malware for process injection, privilege escalation,
keylogging, and C2 communication):

`cmd.exe`, `powershell`, `CreateRemoteThread`, `VirtualAlloc`,
`WriteProcessMemory`, `NtUnmapViewOfSection`, `IsDebuggerPresent`,
`GetProcAddress`, `LoadLibrary`, `WinExec`, `ShellExecute`,
`URLDownloadToFile`, `InternetOpen`, `HttpSendRequest`,
`RegSetValue`, `RegCreateKey`, `CreateService`, `StartService`,
`OpenProcess`, `ReadProcessMemory`, `AdjustTokenPrivileges`,
`LookupPrivilegeValue`, `CryptEncrypt`, `CryptDecrypt`,
`BitBlt`, `keybd_event`, `GetAsyncKeyState`, `SetWindowsHookEx`,
`FindWindow`, `EnumProcesses`, `Process32First`,
`CreateToolhelp32Snapshot`
