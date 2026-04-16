#pragma once
// ============================================================================
// EmberDetector.h  –  LightGBM-based PE malware detector (v4 EMBER)
//
// Uses the LightGBM C API to load a native model file and run inference
// on 2381-feature EMBER vectors, achieving ~96.5% accuracy on real malware.
//
// This replaces the ONNX-based v4 path (which was limited to 86.5% accuracy
// due to distillation into a linear model).
//
// Thread safety: LGBM_BoosterPredictForMatSingleRow is thread-safe.
// ============================================================================

#include <string>
#include <vector>
#include <memory>

class EmberDetector
{
public:
    EmberDetector();
    ~EmberDetector();

    // Non-copyable
    EmberDetector(const EmberDetector&) = delete;
    EmberDetector& operator=(const EmberDetector&) = delete;

    /// Load the LightGBM model and scaler files.
    ///   modelPath:  path to ember_lgbm_model.txt
    ///   scalerPath: path to ember_scaler.bin
    /// Returns true on success.
    bool load(const std::string& modelPath, const std::string& scalerPath);

    /// Returns true if model + scaler are loaded.
    bool isLoaded() const;

    /// Score a raw (unscaled) 2381-feature EMBER vector.
    /// Applies scaling internally, then runs LightGBM inference.
    /// Returns probability of malware in [0.0, 1.0].
    /// Returns -1.0f on error.
    float score(const std::vector<float>& rawFeatures) const;

    /// Convenience: extract EMBER features from a PE file and score it.
    float scoreFile(const std::string& filePath) const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};
