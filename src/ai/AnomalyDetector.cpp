// ============================================================================
// AnomalyDetector.cpp  –  ONNX Runtime inference for anomaly scoring
//
// Uses the ONNX Runtime C++ API to load and run a trained model that
// classifies files as benign (0) or malicious (1) based on the 38-feature
// vector produced by FeatureExtractor.
//
// The model is expected to be a binary classifier exported from scikit-learn
// (via skl2onnx) or XGBoost (via onnxmltools).  The output is either:
//   - A probability array [p_benign, p_malicious]  (we return p_malicious)
//   - A single float score                          (we return it directly)
// ============================================================================

#include "ai/AnomalyDetector.h"
#include "ai/FeatureExtractor.h"

// Guard ONNX Runtime include – if the library isn't available at build time,
// we compile a stub that always returns -1 (model not loaded).
#if __has_include(<onnxruntime_cxx_api.h>)
    #define HAS_ONNXRUNTIME 1
    #include <onnxruntime_cxx_api.h>
#elif __has_include(<onnxruntime/core/session/onnxruntime_cxx_api.h>)
    #define HAS_ONNXRUNTIME 1
    #include <onnxruntime/core/session/onnxruntime_cxx_api.h>
#else
    #define HAS_ONNXRUNTIME 0
#endif

#include <iostream>
#include <algorithm>

// ============================================================================
// PImpl
// ============================================================================

struct AnomalyDetector::Impl
{
#if HAS_ONNXRUNTIME
    Ort::Env            env{ ORT_LOGGING_LEVEL_WARNING, "OdysseusAI" };
    Ort::SessionOptions sessionOpts;
    std::unique_ptr<Ort::Session> session;

    // Cached input/output names (owned strings)
    std::vector<std::string>     inputNames;
    std::vector<std::string>     outputNames;
    std::vector<const char*>     inputNamePtrs;
    std::vector<const char*>     outputNamePtrs;
#endif
    bool loaded = false;
};

// ============================================================================
// Constructor / destructor / move
// ============================================================================

AnomalyDetector::AnomalyDetector()
    : m_impl(std::make_unique<Impl>())
{}

AnomalyDetector::~AnomalyDetector() = default;

AnomalyDetector::AnomalyDetector(AnomalyDetector&&) noexcept = default;
AnomalyDetector& AnomalyDetector::operator=(AnomalyDetector&&) noexcept = default;

// ============================================================================
// loadModel
// ============================================================================

bool AnomalyDetector::loadModel(const std::string& onnxPath)
{
#if HAS_ONNXRUNTIME
    try {
        m_impl->sessionOpts.SetIntraOpNumThreads(1);
        m_impl->sessionOpts.SetGraphOptimizationLevel(
            GraphOptimizationLevel::ORT_ENABLE_ALL);

        // Create session
#ifdef _WIN32
        // Windows needs wide strings for file paths
        std::wstring widePath(onnxPath.begin(), onnxPath.end());
        m_impl->session = std::make_unique<Ort::Session>(
            m_impl->env, widePath.c_str(), m_impl->sessionOpts);
#else
        m_impl->session = std::make_unique<Ort::Session>(
            m_impl->env, onnxPath.c_str(), m_impl->sessionOpts);
#endif

        Ort::AllocatorWithDefaultOptions allocator;

        // Cache input names
        size_t numInputs = m_impl->session->GetInputCount();
        m_impl->inputNames.resize(numInputs);
        m_impl->inputNamePtrs.resize(numInputs);
        for (size_t i = 0; i < numInputs; ++i) {
            auto namePtr = m_impl->session->GetInputNameAllocated(i, allocator);
            m_impl->inputNames[i] = namePtr.get();
            m_impl->inputNamePtrs[i] = m_impl->inputNames[i].c_str();
        }

        // Cache output names
        size_t numOutputs = m_impl->session->GetOutputCount();
        m_impl->outputNames.resize(numOutputs);
        m_impl->outputNamePtrs.resize(numOutputs);
        for (size_t i = 0; i < numOutputs; ++i) {
            auto namePtr = m_impl->session->GetOutputNameAllocated(i, allocator);
            m_impl->outputNames[i] = namePtr.get();
            m_impl->outputNamePtrs[i] = m_impl->outputNames[i].c_str();
        }

        m_impl->loaded = true;
        std::cout << "[AnomalyDetector] Model loaded: " << onnxPath
                  << " (" << numInputs << " inputs, "
                  << numOutputs << " outputs)" << std::endl;
        return true;
    }
    catch (const Ort::Exception& e) {
        std::cerr << "[AnomalyDetector] ONNX error: " << e.what() << std::endl;
        m_impl->loaded = false;
        return false;
    }
#else
    std::cerr << "[AnomalyDetector] ONNX Runtime not available at build time. "
              << "Model loading disabled." << std::endl;
    (void)onnxPath;
    return false;
#endif
}

bool AnomalyDetector::isLoaded() const
{
    return m_impl && m_impl->loaded;
}

// ============================================================================
// score  –  run inference on a feature vector
// ============================================================================

float AnomalyDetector::score(const std::vector<float>& features) const
{
#if HAS_ONNXRUNTIME
    if (!m_impl->loaded || !m_impl->session)
        return -1.0f;

    if (static_cast<int>(features.size()) != kFeatureCount)
        return -1.0f;

    try {
        // Create input tensor
        std::array<int64_t, 2> inputShape = { 1, kFeatureCount };
        auto memInfo = Ort::MemoryInfo::CreateCpu(
            OrtArenaAllocator, OrtMemTypeDefault);

        Ort::Value inputTensor = Ort::Value::CreateTensor<float>(
            memInfo,
            const_cast<float*>(features.data()),
            features.size(),
            inputShape.data(),
            inputShape.size());

        // Run inference
        auto outputTensors = m_impl->session->Run(
            Ort::RunOptions{ nullptr },
            m_impl->inputNamePtrs.data(),
            &inputTensor,
            1,
            m_impl->outputNamePtrs.data(),
            m_impl->outputNamePtrs.size());

        // The model should output probabilities.
        // For sklearn classifiers exported via skl2onnx, output[1] is typically
        // the probability map {0: p_benign, 1: p_malicious}.
        // For a simple model, output[0] might be the label and output[1] the probs.

        // Try to get probability from the last output tensor
        if (outputTensors.size() >= 2) {
            // Probability map output (common for sklearn classifiers)
            auto& probTensor = outputTensors[1];
            auto typeInfo = probTensor.GetTypeInfo();
            auto tensorType = typeInfo.GetTensorTypeAndShapeInfo();
            auto shape = tensorType.GetShape();

            // If it's a map type, we need to handle it differently
            // For standard tensor output [1, 2] = [p_benign, p_malicious]
            const float* probs = probTensor.GetTensorData<float>();
            size_t numProbs = 1;
            for (auto s : shape) numProbs *= s;

            if (numProbs >= 2) {
                // Return probability of class 1 (malicious)
                return std::clamp(probs[1], 0.0f, 1.0f);
            } else if (numProbs == 1) {
                return std::clamp(probs[0], 0.0f, 1.0f);
            }
        }

        // Fallback: single output tensor
        if (!outputTensors.empty()) {
            const float* data = outputTensors[0].GetTensorData<float>();
            return std::clamp(data[0], 0.0f, 1.0f);
        }

        return -1.0f;
    }
    catch (const Ort::Exception& e) {
        std::cerr << "[AnomalyDetector] Inference error: " << e.what() << std::endl;
        return -1.0f;
    }
#else
    (void)features;
    return -1.0f;
#endif
}

// ============================================================================
// scoreFile  –  convenience wrapper
// ============================================================================

float AnomalyDetector::scoreFile(const std::string& filePath) const
{
    auto features = extractFeatures(filePath);
    if (features.empty())
        return -1.0f;
    return score(features);
}
