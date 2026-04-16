#pragma once
// ============================================================================
// AnomalyDetector.h  –  ONNX Runtime inference wrapper for anomaly scoring
//
// Loads a trained ONNX model (gradient boosted tree or similar) and runs
// inference on 38-feature vectors produced by FeatureExtractor.
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
    /// Call this once at startup; the model stays resident in memory.
    bool loadModel(const std::string& onnxPath);

    /// Returns true if a model is currently loaded.
    bool isLoaded() const;

    /// Run inference on a 38-element feature vector.
    /// Returns a score in [0.0, 1.0] where higher = more suspicious.
    /// Returns -1.0f on error (model not loaded, wrong feature count, etc.)
    float score(const std::vector<float>& features) const;

    /// Convenience: extract features from a file path and score it.
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
