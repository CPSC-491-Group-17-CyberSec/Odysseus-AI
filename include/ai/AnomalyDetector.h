#pragma once
// ============================================================================
// AnomalyDetector.h  –  ONNX Runtime inference wrapper for anomaly scoring
//
// Loads a trained ONNX model and runs inference on feature vectors produced
// by FeatureExtractor.  Supports multiple model sizes:
//   - v2/v3: 38-feature vectors (general file anomaly detection)
//   - v4:    2381-feature vectors (EMBER PE malware detection)
//
// The model's expected input dimension is auto-detected at load time.
//
// Thread safety: the Ort::Session is thread-safe for concurrent Run() calls
// as long as each call uses its own Ort::Value tensors (which we do).
// ============================================================================

#include <string>
#include <vector>
#include <memory>

// Forward-declare ONNX Runtime types to avoid leaking the header into every TU.
// The implementation includes the real headers.
namespace Ort {
    struct Env;
    struct Session;
    struct SessionOptions;
    struct MemoryInfo;
}

class AnomalyDetector
{
public:
    AnomalyDetector();
    ~AnomalyDetector();

    // Non-copyable, movable
    AnomalyDetector(const AnomalyDetector&) = delete;
    AnomalyDetector& operator=(const AnomalyDetector&) = delete;
    AnomalyDetector(AnomalyDetector&&) noexcept;
    AnomalyDetector& operator=(AnomalyDetector&&) noexcept;

    /// Load an ONNX model from disk.  Returns true on success.
    /// Auto-detects input feature count from the model.
    bool loadModel(const std::string& onnxPath);

    /// Returns true if a model is currently loaded.
    bool isLoaded() const;

    /// Number of features the loaded model expects (38 for v2/v3, 2381 for v4).
    /// Returns 0 if no model is loaded.
    int expectedFeatureCount() const;

    /// Run inference on a feature vector.
    /// The vector size must match expectedFeatureCount().
    /// Returns a score in [0.0, 1.0] where higher = more suspicious.
    /// Returns -1.0f on error (model not loaded, wrong feature count, etc.)
    float score(const std::vector<float>& features) const;

    /// Convenience: extract features from a file path and score it.
    /// Uses the 38-feature extractor (v2/v3 models only).
    float scoreFile(const std::string& filePath) const;

    /// Threshold above which a file is considered "suspicious".
    /// Default 0.5; callers can adjust.
    float threshold() const { return m_threshold; }
    void  setThreshold(float t) { m_threshold = t; }

private:
    struct Impl;                     // PImpl to hide ONNX headers
    std::unique_ptr<Impl> m_impl;
    float m_threshold = 0.5f;
};
