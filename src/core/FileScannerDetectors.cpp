// ============================================================================
// FileScannerDetectors.cpp  –  AI-based anomaly detection + LLM explanation
//
// This file implements checkByAI(), a second detection stage that runs after
// the hash-based lookup in FileScannerHash.cpp.  It uses the trained ONNX
// model (via AnomalyDetector) to score files that did NOT match a known
// malware hash, catching unknown/obfuscated/zero-day threats.
//
// When a file IS flagged, the LLMExplainer module is called asynchronously
// to generate a human-readable explanation of the threat via a locally
// running Ollama instance (e.g. llama3).  The explanation is delivered
// via the outExplanation parameter and displayed in the UI.
//
// Integration point: called from runHashWorker() in FileScannerHash.cpp
// after checkByHash() returns false.
//
// Thread safety: AnomalyDetector::score() is safe to call from multiple
// threads simultaneously (each call creates its own ONNX tensor).
// LLMExplainer::explain() is also thread-safe (each call creates its own
// QNetworkAccessManager).
// ============================================================================

#include "FileScanner.h"
#include "ai/AnomalyDetector.h"
#include "ai/FeatureExtractor.h"
#include "ai/LLMExplainer.h"

#include <QCoreApplication>
#include <QFileInfo>
#include <QMutex>
#include <iostream>

// ============================================================================
// Singleton detector – loaded once, shared by all scanner instances
// ============================================================================
namespace {

QMutex g_detectorInitMutex;
AnomalyDetector* g_detector = nullptr;
bool g_initAttempted = false;

/// Lazy-initialize the global AnomalyDetector.
/// Searches for the ONNX model file in standard locations relative to
/// the application binary (mirrors how malware_hashes.txt is found).
AnomalyDetector* getDetector()
{
    QMutexLocker lock(&g_detectorInitMutex);

    if (g_initAttempted)
        return g_detector;

    g_initAttempted = true;

    const QString appDir = QCoreApplication::applicationDirPath();
    const QStringList candidates = {
        appDir + "/data/anomaly_model.onnx",
        appDir + "/../data/anomaly_model.onnx",
        appDir + "/../../data/anomaly_model.onnx",
        appDir + "/../../../data/anomaly_model.onnx",
    };

    for (const QString& path : candidates) {
        if (!QFileInfo::exists(path))
            continue;

        auto* det = new AnomalyDetector();
        if (det->loadModel(path.toStdString())) {
            g_detector = det;
            std::cout << "[FileScannerDetectors] AI model loaded from "
                      << path.toStdString() << std::endl;
            return g_detector;
        }
        delete det;
    }

    std::cout << "[FileScannerDetectors] No anomaly_model.onnx found. "
              << "AI detection disabled (hash-only mode)." << std::endl;
    return nullptr;
}

// ============================================================================
// Singleton LLM explainer – initialized once, shared across threads
// ============================================================================
QMutex g_llmInitMutex;
LLMExplainer* g_explainer = nullptr;
bool g_llmInitAttempted = false;

/// Lazy-initialize the global LLMExplainer.
/// Checks if Ollama is reachable; if not, LLM explanations are disabled.
LLMExplainer* getExplainer()
{
    QMutexLocker lock(&g_llmInitMutex);

    if (g_llmInitAttempted)
        return g_explainer;

    g_llmInitAttempted = true;

    auto* exp = new LLMExplainer();

    if (exp->isAvailable()) {
        g_explainer = exp;
        std::cout << "[FileScannerDetectors] Ollama is running – "
                  << "LLM threat explanations enabled (model: "
                  << exp->config().model << ")" << std::endl;
        return g_explainer;
    }

    delete exp;
    std::cout << "[FileScannerDetectors] Ollama not reachable – "
              << "LLM explanations disabled. "
              << "Install & run: brew install ollama && ollama serve && ollama pull llama3"
              << std::endl;
    return nullptr;
}

}  // anonymous namespace

// ============================================================================
// checkByAI  –  public function called from the hash worker
//
// Returns true if the file is flagged as suspicious by the ML model.
// Populates outReason, outCategory, and optionally outExplanation.
// ============================================================================
bool checkByAI(const QString& filePath,
               qint64         fileSize,
               QString&       outReason,
               QString&       outCategory)
{
    // Skip very small files (not enough signal) and very large files (perf)
    if (fileSize < 256 || fileSize > 100LL * 1024 * 1024)
        return false;

    AnomalyDetector* det = getDetector();
    if (!det)
        return false;

    // Extract features first (needed for both scoring and LLM explanation)
    std::vector<float> features = extractFeatures(filePath.toStdString());
    if (features.empty())
        return false;

    // Run the ML model
    float anomalyScore = det->score(features);

    if (anomalyScore < 0.0f)
        return false;  // extraction or inference error

    if (anomalyScore >= det->threshold()) {
        outCategory = "AI Anomaly Detection";
        outReason   = QString("ML model flagged file as suspicious "
                              "(anomaly score: %1, threshold: %2)")
                          .arg(anomalyScore, 0, 'f', 3)
                          .arg(det->threshold(), 0, 'f', 3);

        // --- LLM explanation (synchronous for now, ~5-15 seconds) ---
        // If Ollama is running, generate a human-readable explanation
        // of why this file was flagged and what to do about it.
        LLMExplainer* exp = getExplainer();
        if (exp) {
            std::string explanation = exp->explain(
                filePath.toStdString(), features, anomalyScore);

            if (!explanation.empty() &&
                explanation.find("[LLM Explainer]") == std::string::npos)
            {
                // Append the explanation to the reason field so it shows in the UI
                outReason += "\n\n--- AI Analysis ---\n"
                             + QString::fromStdString(explanation);
            }
        }

        return true;
    }

    return false;
}
