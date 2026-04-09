// ============================================================================
// FileScannerDetectors.cpp  –  AI-based anomaly detection pass
//
// This file implements checkByAI(), a second detection stage that runs after
// the hash-based lookup in FileScannerHash.cpp.  It uses the trained ONNX
// model (via AnomalyDetector) to score files that did NOT match a known
// malware hash, catching unknown/obfuscated/zero-day threats.
//
// Integration point: called from runHashWorker() in FileScannerHash.cpp
// after checkByHash() returns false.
//
// Thread safety: AnomalyDetector::score() is safe to call from multiple
// threads simultaneously (each call creates its own ONNX tensor).
// ============================================================================

#include "FileScanner.h"
#include "ai/AnomalyDetector.h"
#include "ai/FeatureExtractor.h"


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

}  // anonymous namespace

// ============================================================================
// checkByAI  –  public function called from the hash worker
//
// Returns true if the file is flagged as suspicious by the ML model.
// Populates outReason and outCategory for the SuspiciousFile struct.
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

    float anomalyScore = det->scoreFile(filePath.toStdString());

    if (anomalyScore < 0.0f)
        return false;  // extraction or inference error

    if (anomalyScore >= det->threshold()) {
        outCategory = "AI Anomaly Detection";
        outReason   = QString("ML model flagged file as suspicious "
                              "(anomaly score: %1, threshold: %2)")
                          .arg(anomalyScore, 0, 'f', 3)
                          .arg(det->threshold(), 0, 'f', 3);
        return true;
    }

    return false;
}
