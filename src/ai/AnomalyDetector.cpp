// ============================================================================
// AnomalyDetector.cpp  –  ONNX Runtime inference for anomaly scoring
//
// Uses the ONNX Runtime C++ API to load and run a trained model that
// classifies files as benign (0) or malicious (1).  Supports:
//   - v2/v3 models: 38-feature vectors (general anomaly detection)
//   - v4 model:     2381-feature vectors (EMBER PE malware detection)
//
// The expected input dimension is auto-detected from the model at load time.
//
// The output is either:
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
#include <iomanip>
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
    int featureCount = 0;        // auto-detected from model input shape
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

        // Auto-detect expected feature count from input shape
        // Input shape is typically [N, featureCount] or [-1, featureCount]
        auto inputTypeInfo = m_impl->session->GetInputTypeInfo(0);
        auto inputShape = inputTypeInfo.GetTensorTypeAndShapeInfo().GetShape();
        if (inputShape.size() >= 2 && inputShape[1] > 0) {
            m_impl->featureCount = static_cast<int>(inputShape[1]);
        } else {
            m_impl->featureCount = 38;  // fallback for dynamic shapes
        }

        m_impl->loaded = true;
        std::cout << "[AnomalyDetector] Model loaded: " << onnxPath
                  << " (" << numInputs << " inputs, "
                  << numOutputs << " outputs, "
                  << m_impl->featureCount << " features)" << std::endl;
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

int AnomalyDetector::expectedFeatureCount() const
{
#if HAS_ONNXRUNTIME
    if (m_impl && m_impl->loaded)
        return m_impl->featureCount;
#endif
    return 0;
}

// ============================================================================
// score  –  run inference on a feature vector
// ============================================================================

float AnomalyDetector::score(const std::vector<float>& features) const
{
#if HAS_ONNXRUNTIME
    if (!m_impl->loaded || !m_impl->session)
        return -1.0f;

    const int expectedCount = m_impl->featureCount;
    if (static_cast<int>(features.size()) != expectedCount)
        return -1.0f;

    try {
        // Create input tensor
        std::array<int64_t, 2> inputShape = { 1, static_cast<int64_t>(expectedCount) };
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

        // ── Diagnostic: dump all output tensors ────────────────────────
        // This logging is critical for diagnosing score pipeline issues.
        // Set ODYSSEUS_DIAG=1 env var to enable, or always enable in debug.
        bool diagEnabled = true;  // TODO: gate behind env var for production
        if (diagEnabled && !outputTensors.empty()) {
            std::cout << "[DIAG:ONNX] " << outputTensors.size() << " output tensor(s)";
            for (size_t t = 0; t < outputTensors.size(); ++t) {
                auto ti = outputTensors[t].GetTypeInfo();
                auto si = ti.GetTensorTypeAndShapeInfo();
                auto shape = si.GetShape();
                const float* td = outputTensors[t].GetTensorData<float>();
                size_t n = 1;
                for (auto s : shape) n *= s;
                std::cout << "  |  output[" << t << "] shape=[";
                for (size_t i = 0; i < shape.size(); ++i) {
                    if (i > 0) std::cout << ",";
                    std::cout << shape[i];
                }
                std::cout << "] vals=[";
                for (size_t i = 0; i < std::min(n, size_t(8)); ++i) {
                    if (i > 0) std::cout << ", ";
                    std::cout << std::fixed << std::setprecision(6) << td[i];
                }
                if (n > 8) std::cout << " ...";
                std::cout << "]";
            }
            std::cout << std::endl;
        }

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
                float pBenign    = probs[0];
                float pMalicious = probs[1];
                if (diagEnabled) {
                    std::cout << "[DIAG:ONNX] p(benign)=" << std::fixed
                              << std::setprecision(6) << pBenign
                              << "  p(malicious)=" << pMalicious
                              << "  RETURNING=" << std::clamp(pMalicious, 0.0f, 1.0f)
                              << std::endl;
                }
                return std::clamp(pMalicious, 0.0f, 1.0f);
            } else if (numProbs == 1) {
                if (diagEnabled) {
                    std::cout << "[DIAG:ONNX] single-prob output="
                              << std::fixed << std::setprecision(6) << probs[0]
                              << std::endl;
                }
                return std::clamp(probs[0], 0.0f, 1.0f);
            }
        }

        // Fallback: single output tensor
        if (!outputTensors.empty()) {
            const float* data = outputTensors[0].GetTensorData<float>();
            if (diagEnabled) {
                std::cout << "[DIAG:ONNX] fallback single-tensor output="
                          << std::fixed << std::setprecision(6) << data[0]
                          << std::endl;
            }
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
