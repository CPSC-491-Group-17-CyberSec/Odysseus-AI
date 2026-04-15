// ============================================================================
// FileScannerDetectors.cpp  –  AI-based anomaly detection + LLM explanation
//
// Architecture: Two-stage pipeline with clean separation of concerns.
//
//   Stage 1 — DETECTION + CLASSIFICATION (Phase 2: calibrated pipeline)
//     • Extracts 38-feature vector from file bytes
//     • Runs ONNX inference to produce raw anomaly score (0.0–1.0)
//     • Calibrates the raw score through a per-type calibration curve
//       (e.g. HTML raw 0.75 → calibrated 0.15 because HTML inflates scores)
//     • Computes weighted indicator strength with per-type feature weights
//     • Blends calibrated score + indicator score for final risk assessment
//     • Classifies into Clean / Anomalous / Suspicious / Critical
//     • Web/text files with only weak indicators are suppressed as Clean
//
//   Stage 2 — EXPLANATION (Ollama LLM via LLMExplainer)
//     • Sends structured prompt with classification level + features
//     • Anomalous files get cautious "may warrant review" language
//     • Suspicious/Critical files get direct threat language
//     • Falls back gracefully if Ollama is unavailable
//
// Integration point: called from runHashWorker() in FileScannerHash.cpp
// after checkByHash() returns false.
//
// Thread safety: AnomalyDetector::score() and LLMExplainer::explain() are
// both safe to call from multiple threads simultaneously.
// ============================================================================

#include "FileScanner.h"
#include "ai/AnomalyDetector.h"
#include "ai/FeatureExtractor.h"
#include "ai/LLMExplainer.h"
#include "ai/ScanResultFormatter.h"
#include "ai/FileTypeScoring.h"

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
AnomalyDetector* getDetector()
{
    QMutexLocker lock(&g_detectorInitMutex);

    if (g_initAttempted)
        return g_detector;

    g_initAttempted = true;

    const QString appDir = QCoreApplication::applicationDirPath();
    const QStringList candidates = {
        appDir + "/data/anomaly_model_v2.onnx",
        appDir + "/../data/anomaly_model_v2.onnx",
        appDir + "/../../data/anomaly_model_v2.onnx",
        appDir + "/../../../data/anomaly_model_v2.onnx",
    };

    for (const QString& path : candidates) {
        if (!QFileInfo::exists(path))
            continue;

        auto* det = new AnomalyDetector();
        if (det->loadModel(path.toStdString())) {
            g_detector = det;
            std::cout << "[AI] Model loaded: " << path.toStdString() << std::endl;
            return g_detector;
        }
        delete det;
    }

    std::cout << "[AI] No anomaly_model_v2.onnx found — hash-only mode." << std::endl;
    return nullptr;
}

// ============================================================================
// Singleton LLM explainer – initialized once, shared across threads
// ============================================================================
QMutex g_llmInitMutex;
LLMExplainer* g_explainer = nullptr;
bool g_llmInitAttempted = false;

LLMExplainer* getExplainer()
{
    QMutexLocker lock(&g_llmInitMutex);

    if (g_llmInitAttempted)
        return g_explainer;

    g_llmInitAttempted = true;

    auto* exp = new LLMExplainer();

    if (exp->isAvailable()) {
        g_explainer = exp;
        std::cout << "[AI] Ollama connected (model: "
                  << exp->config().model << ")" << std::endl;
        return g_explainer;
    }

    delete exp;
    std::cout << "[AI] Ollama not reachable — LLM explanations disabled."
              << std::endl;
    return nullptr;
}

}  // anonymous namespace

// ============================================================================
// checkByAI  –  public function called from the hash worker
//
// Returns true if the file is flagged (Anomalous, Suspicious, or Critical).
// Returns false for Clean files (including suppressed web false positives).
//
// Phase 2 Pipeline:
//   1. Extract features (FeatureExtractor)
//   2. Score with ONNX model (AnomalyDetector) → raw score
//   3. Calibrate raw score through per-type calibration curve
//   4. Compute weighted indicator strength with per-type feature weights
//   5. Blend calibrated score + indicator score → final risk score
//   6. Classify using per-type thresholds + indicator requirements
//   7. Return false if Clean (web files with only weak indicators, etc.)
//   8. Query Ollama for explanation (classification-aware wording)
//   9. Format clean terminal output (single, deduplicated print)
// ============================================================================
bool checkByAI(const QString& filePath,
               qint64         fileSize,
               QString&       outReason,
               QString&       outCategory,
               SuspiciousFile* outDetails)
{
    // Skip very small files (not enough signal) and very large files (perf)
    if (fileSize < 256 || fileSize > 100LL * 1024 * 1024)
        return false;

    AnomalyDetector* det = getDetector();
    if (!det)
        return false;

    // ── Stage 1: DETECTION (ONNX Model) ──────────────────────────────────

    std::vector<float> features = extractFeatures(filePath.toStdString());
    if (features.empty())
        return false;

    float rawScore = det->score(features);
    if (rawScore < 0.0f)
        return false;  // extraction or inference error

    // ── CLASSIFICATION (Phase 2: calibrated per-type pipeline) ───────────
    std::string ext = extractExtension(filePath.toStdString());
    float baseThreshold = det->threshold();

    // If extension-based categorization returns Unknown, try filename-based
    // (handles Makefile, CMakeLists.txt, etc.)
    if (categorizeExtension(ext) == FileCategory::Unknown) {
        std::string filename = QFileInfo(filePath).fileName().toStdString();
        FileCategory filenameCat = categorizeFilename(filename);
        if (filenameCat != FileCategory::Unknown) {
            // Use a synthetic extension that maps to the right category
            // The calibrated classifier will pick up the correct profile
            if (filenameCat == FileCategory::BuildOutput)
                ext = "cmake";  // maps to BuildOutput in categorizeExtension
        }
    }

    ClassificationResult cr = classifyFileCalibrated(rawScore, baseThreshold, ext, features);

    // ── POST-CLASSIFICATION: path-aware severity downgrade ──────────────
    // These rules cap the classification for files that are contextually
    // benign despite triggering the model.  They do NOT modify the ONNX
    // score, features, or core scoring pipeline — only the final verdict.
    {
        const std::string path = filePath.toStdString();
        // Convert to lowercase for case-insensitive fragment matching
        std::string lpath = path;
        std::transform(lpath.begin(), lpath.end(), lpath.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        bool shouldCap = false;
        std::string capReason;

        // ── Rule 1: Build artifacts ────────────────────────────────────
        // Compiled binaries inside build directories are project outputs,
        // not threats. High entropy + embedded strings are expected.
        if (lpath.find("/build/") != std::string::npos ||
            lpath.find("/cmake-build-") != std::string::npos ||
            lpath.find("/cmakefiles/") != std::string::npos)
        {
            shouldCap = true;
            capReason = "Build artifact (in build directory)";
        }

        // ── Rule 2: Chromium / Electron resource files ─────────────────
        // .pak files and code-cache entries inside browser/Electron apps
        // have high entropy, embedded URLs, and base64 by design.
        if (ext == "pak" ||
            lpath.find("chromium embedded framework") != std::string::npos ||
            lpath.find("code cache")   != std::string::npos ||
            lpath.find("/electron/")   != std::string::npos ||
            lpath.find("/electron.app/") != std::string::npos ||
            lpath.find(".app/contents/resources/") != std::string::npos ||
            lpath.find("nwjs")         != std::string::npos)
        {
            shouldCap = true;
            capReason = "Chromium/Electron resource";
        }

        // ── Rule 3: System/app managed directories ─────────────────────
        // Files in Homebrew, Xcode toolchains, system frameworks, and
        // macOS app bundles are signed and managed by the OS / package
        // manager.  Flag for review at most, never as Suspicious/Critical.
        if (lpath.find("/cellar/")              != std::string::npos ||
            lpath.find("/homebrew/")            != std::string::npos ||
            lpath.find(".app/contents/macos/")  != std::string::npos ||
            lpath.find(".app/contents/frameworks/") != std::string::npos ||
            lpath.find("/deriveddata/")         != std::string::npos ||
            lpath.find("/xcode.app/")           != std::string::npos ||
            lpath.find("/library/frameworks/")  != std::string::npos ||
            lpath.find("/site-packages/")       != std::string::npos ||
            lpath.find("/node_modules/")        != std::string::npos)
        {
            shouldCap = true;
            capReason = "Managed system/app directory";
        }

        // Apply the cap: downgrade Suspicious/Critical → Anomalous
        if (shouldCap &&
            (cr.level == ClassificationLevel::Suspicious ||
             cr.level == ClassificationLevel::Critical))
        {
            std::cout << "[POST-CLASS] Downgrading "
                      << QFileInfo(filePath).fileName().toStdString()
                      << " from " << classificationToString(cr.level)
                      << " → Anomalous (" << capReason << ")\n";
            cr.level    = ClassificationLevel::Anomalous;
            cr.severity = SeverityLevel::Low;
            cr.suppressed = true;
        }
    }

    // ── DIAGNOSTIC: full pipeline dump for every file ────────────────────
    // This is the single most important diagnostic block.  It lets you see
    // the entire pipeline: raw features → raw ONNX score → calibrated score
    // → indicators → verdict.  Run against benign validation files to
    // determine whether the problem is model, calibration, or classification.
    {
        FileCategory diagCat = categorizeExtension(ext);
        const FileTypeProfile& diagProfile = FileTypeProfiles::getProfile(diagCat);
        float calibrated = diagProfile.calibration.calibrate(rawScore);
        WeightedIndicatorResult diagInd = computeWeightedIndicators(features, diagProfile);
        float blend = diagProfile.weights.indicatorBlendFactor;
        float finalScore = (1.0f - blend) * calibrated + blend * diagInd.score;

        std::cout << "\n[DIAG:PIPELINE] ──────────────────────────────────────\n"
                  << "[DIAG:PIPELINE] File:       " << QFileInfo(filePath).fileName().toStdString() << "\n"
                  << "[DIAG:PIPELINE] Extension:  ." << ext << "\n"
                  << "[DIAG:PIPELINE] Category:   " << fileCategoryToString(diagCat) << "\n"
                  << "[DIAG:PIPELINE] ─── Features (key) ───\n"
                  << std::fixed << std::setprecision(3)
                  << "[DIAG:PIPELINE]   entropy=" << features[1]
                  << "  printableASCII=" << features[6]
                  << "  highByteRatio=" << features[7] << "\n"
                  << "[DIAG:PIPELINE]   isPE=" << features[16]
                  << "  suspiciousAPIs=" << features[32]
                  << "  urls=" << features[33]
                  << "  ips=" << features[34] << "\n"
                  << "[DIAG:PIPELINE]   registryPaths=" << features[35]
                  << "  base64=" << features[36] << "\n"
                  << "[DIAG:PIPELINE] ─── Score Pipeline ───\n"
                  << "[DIAG:PIPELINE]   RAW ONNX score:   " << rawScore << "\n"
                  << "[DIAG:PIPELINE]   Calibrated score:  " << calibrated << "\n"
                  << "[DIAG:PIPELINE]   Indicator score:   " << diagInd.score << "\n"
                  << "[DIAG:PIPELINE]   Blend factor:      " << blend << "\n"
                  << "[DIAG:PIPELINE]   FINAL score:       " << finalScore << "\n"
                  << "[DIAG:PIPELINE]   Strong indicators: " << diagInd.strongCount << "\n"
                  << "[DIAG:PIPELINE]   Weak indicators:   " << diagInd.weakCount << "\n"
                  << "[DIAG:PIPELINE] ─── Thresholds ───\n"
                  << "[DIAG:PIPELINE]   cleanCeiling:      " << diagProfile.cleanCeiling << "\n"
                  << "[DIAG:PIPELINE]   anomalousCeiling:   " << diagProfile.anomalousCeiling << "\n"
                  << "[DIAG:PIPELINE]   suspiciousCeiling:  " << diagProfile.suspiciousCeiling << "\n"
                  << "[DIAG:PIPELINE] ─── Verdict ───\n"
                  << "[DIAG:PIPELINE]   Classification:    " << classificationToString(cr.level)
                  << (cr.suppressed ? " (SUPPRESSED)" : "") << "\n"
                  << "[DIAG:PIPELINE] ──────────────────────────────────────\n"
                  << std::flush;
    }

    // Clean files (including suppressed web false positives) are NOT flagged
    if (cr.level == ClassificationLevel::Clean)
        return false;

    // ── Compute weighted indicators for display ──────────────────────────
    FileCategory fileCat = cr.fileCategory;
    const FileTypeProfile& profile = FileTypeProfiles::getProfile(fileCat);
    WeightedIndicatorResult weightedInd = computeWeightedIndicators(features, profile);

    // ── Build structured ScanResult ──────────────────────────────────────
    ScanResult result;
    result.filePath           = filePath.toStdString();
    result.fileName           = QFileInfo(filePath).fileName().toStdString();
    result.anomalyScore       = rawScore;
    result.threshold          = baseThreshold;
    result.effectiveThreshold = cr.effectiveThreshold;
    result.classification     = cr.level;
    result.severity           = cr.severity;
    result.fileCategory       = cr.fileCategory;
    result.isSuspicious       = true;
    result.fileExtension      = ext;
    result.features           = features;

    // Extract key indicators from the weighted analysis (Phase 2)
    // Strong indicators come first; weak ones are tagged [Expected]
    result.keyIndicators = weightedInd.strongIndicators;
    for (const auto& wi : weightedInd.weakIndicators) {
        if (result.keyIndicators.size() >= 4) break;  // limit display
        result.keyIndicators.push_back("[Expected] " + wi);
    }
    if (result.keyIndicators.empty())
        result.keyIndicators.push_back("Statistical anomaly in byte distribution patterns");

    // ── Developer file check (used by LLM + default actions/summary) ────
    bool isDeveloperFile = (fileCat == FileCategory::SourceCode ||
                            fileCat == FileCategory::CompiledArtifact ||
                            fileCat == FileCategory::BuildOutput);

    // ── Embedded AI: classification-aware default actions ────────────────
    // Always generate embedded AI defaults first; LLM may enhance later.
    if (isDeveloperFile) {
        result.recommendedActions = {
            "Verify this file is part of your project or a known tool",
            "Check if the flagged patterns are expected for this file type",
            "If the file is unfamiliar, review its origin and last modification date"
        };
    } else if (cr.level == ClassificationLevel::Anomalous) {
        result.recommendedActions = {
            "Review the file manually to determine if it is expected",
            "Check the file's origin and whether it was recently modified",
            "If uncertain, submit the file hash to VirusTotal for verification"
        };
    } else if (cr.level == ClassificationLevel::Suspicious) {
        result.recommendedActions = {
            "Quarantine the file and prevent execution",
            "Submit file hash to VirusTotal for multi-engine verification",
            "Review system logs for signs of prior execution"
        };
    } else {  // Critical
        result.recommendedActions = {
            "Quarantine the file immediately and prevent execution",
            "Submit file hash to VirusTotal for multi-engine verification",
            "Review system logs for signs of prior execution",
            "Scan connected systems for lateral movement indicators"
        };
    }

    // ── Embedded AI: classification-aware default summary ─────────────
    if (isDeveloperFile) {
        result.aiSummary =
            "This appears to be a development artifact. The ML model "
            "detected unusual patterns, but developer files commonly contain "
            "security-related keywords, API references, and encoded strings "
            "as part of normal tooling. Manual review recommended; legitimate "
            "tooling is likely.";
    } else if (cr.level == ClassificationLevel::Anomalous) {
        result.aiSummary =
            "The ML model detected statistical patterns that differ from "
            "typical benign files. This may be a false positive and warrants "
            "manual review before taking action.";
    } else if (cr.level == ClassificationLevel::Suspicious) {
        result.aiSummary =
            "The ML anomaly detection model flagged this file based on "
            "multiple indicators of potentially malicious behavior. "
            "The file exhibits characteristics inconsistent with benign software.";
    } else {  // Critical
        result.aiSummary =
            "The ML model detected strong indicators of malicious intent "
            "including multiple high-confidence signals. Immediate action "
            "is recommended.";
    }

    // ── LLM EXPLANATION ────────────────────────────────────────────────
    // LLM explanations are now generated ON-DEMAND when the user selects
    // a finding in the UI (MainWindow).  This eliminates inconsistency
    // caused by parallel LLM calls during the scan pipeline.
    //
    // The scan only checks whether Ollama is reachable so the dashboard
    // can display the correct status indicator.
    bool llmWasAvailable = (getExplainer() != nullptr);

    // ── Terminal output (single, clean print — no duplicates) ────────────
    std::cout << formatTerminalOutput(result) << std::flush;

    // ── Populate output parameters for UI ────────────────────────────────
    outCategory = "AI Anomaly Detection";

    // Build structured reason string
    QString reasonText;
    reasonText += QString("Classification: %1 | Score: %2 | Threshold: %3\n")
                      .arg(QString::fromStdString(classificationToString(cr.level)))
                      .arg(rawScore, 0, 'f', 3)
                      .arg(cr.effectiveThreshold, 0, 'f', 3);

    reasonText += "\nKey Indicators:\n";
    for (const auto& ind : result.keyIndicators)
        reasonText += QString::fromUtf8("  \u2022 ") + QString::fromStdString(ind) + "\n";

    reasonText += "\nAI Summary:\n" + QString::fromStdString(result.aiSummary) + "\n";

    reasonText += "\nRecommended Actions:\n";
    for (size_t i = 0; i < result.recommendedActions.size(); ++i) {
        reasonText += QString("  %1. %2\n")
                          .arg(i + 1)
                          .arg(QString::fromStdString(result.recommendedActions[i]));
    }

    outReason = reasonText;

    // ── Populate optional SuspiciousFile metadata ────────────────────────
    if (outDetails) {
        outDetails->anomalyScore     = rawScore;
        outDetails->anomalyThreshold = cr.effectiveThreshold;
        outDetails->severityLevel    = QString::fromStdString(severityToString(cr.severity));
        outDetails->classificationLevel = QString::fromStdString(classificationToString(cr.level));
        outDetails->aiSummary        = QString::fromStdString(result.aiSummary);

        QStringList qIndicators;
        for (const auto& ind : result.keyIndicators)
            qIndicators.append(QString::fromStdString(ind));
        outDetails->keyIndicators = qIndicators;

        QStringList qActions;
        for (const auto& act : result.recommendedActions)
            qActions.append(QString::fromStdString(act));
        outDetails->recommendedActions = qActions;

        // LLM explanation is generated on-demand in the UI; leave empty here.
        // Only store the Ollama availability flag for dashboard status.
        outDetails->llmAvailable  = llmWasAvailable;
    }

    return true;
}
