// ============================================================================
// LLMExplainer.cpp  –  Ollama-based local LLM threat explanation
//
// Sends feature data from flagged files to a locally running Ollama
// instance and returns a human-readable analysis.  Falls back gracefully
// if Ollama is not running — the scanner continues to work without
// explanations.
//
// Classification-aware prompting:
//   • Anomalous  → cautious wording: "may warrant review", "could be benign"
//   • Suspicious → direct: "exhibits suspicious characteristics"
//   • Critical   → urgent: "strong indicators of malicious intent"
//
// Network layer: uses Qt's QNetworkAccessManager for HTTP POST to Ollama.
// ============================================================================

#include "ai/LLMExplainer.h"
#include "ai/FeatureExtractor.h"

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QEventLoop>
#include <QTimer>
#include <QUrl>
#include <QFileInfo>
#include <QThread>

#include <sstream>
#include <iomanip>
#include <iostream>
#include <thread>

// ============================================================================
// Construction
// ============================================================================

LLMExplainer::LLMExplainer() : m_config{} {}

LLMExplainer::LLMExplainer(const Config& config) : m_config(config) {}

LLMExplainer::~LLMExplainer() = default;

void LLMExplainer::setConfig(const Config& config) { m_config = config; }

// ============================================================================
// isAvailable  –  quick health check against Ollama
// ============================================================================
bool LLMExplainer::isAvailable() const
{
    QNetworkAccessManager mgr;
    QNetworkRequest req(QUrl(QString::fromStdString(
        "http://localhost:11434/api/tags")));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QNetworkReply* reply = mgr.get(req);

    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    timer.start(5000);
    loop.exec();

    bool ok = reply->isFinished() &&
              reply->error() == QNetworkReply::NoError;
    reply->deleteLater();
    return ok;
}

// ============================================================================
// buildPrompt  –  classification-aware structured analysis prompt
//
// The prompt tone adapts to the classification level:
//   Anomalous  → "This file MAY warrant review. Be cautious about
//                  over-stating risk. It could be a false positive."
//   Suspicious → Standard security analysis tone
//   Critical   → "High confidence malicious. Be direct about the threat."
// ============================================================================
std::string LLMExplainer::buildPrompt(const std::string& filePath,
                                       const std::vector<float>& features,
                                       float anomalyScore,
                                       const std::string& classificationLevel) const
{
    QFileInfo fi(QString::fromStdString(filePath));
    std::ostringstream ss;

    // ── System instruction: role + output format ────────────────────────
    ss << "You are a concise cybersecurity analyst. A file was flagged by our "
       << "ML anomaly detection engine. ";

    // Classification-aware tone instruction
    if (classificationLevel == "Anomalous") {
        ss << "IMPORTANT: This file is classified as ANOMALOUS (borderline). "
           << "It may be a false positive. Use cautious, measured language. "
           << "Say 'may warrant review' instead of 'is suspicious'. "
           << "Say 'could indicate' instead of 'indicates'. "
           << "Acknowledge the possibility of a false positive in the summary. "
           << "Do NOT overstate the threat level.\n\n";
    } else if (classificationLevel == "Anomalous-Developer") {
        ss << "IMPORTANT: This file is a DEVELOPER ARTIFACT (source code, "
           << "compiled object, or build configuration). It is classified as "
           << "ANOMALOUS but is very likely a false positive. Developer files "
           << "commonly contain security-related keywords, API references, "
           << "encoded strings, and registry paths as part of normal tooling. "
           << "Use very soft language: 'unusual developer artifact', "
           << "'needs review', 'legitimate tooling is likely'. "
           << "Do NOT recommend quarantine or blocking. Suggest manual review.\n\n";
    } else if (classificationLevel == "CRITICAL") {
        ss << "This file is classified as CRITICAL — high confidence malicious. "
           << "Be direct about the threat. Use definitive language.\n\n";
    } else {
        ss << "This file is classified as SUSPICIOUS. "
           << "Provide a balanced security analysis.\n\n";
    }

    ss << "Respond in EXACTLY this format (no markdown, no extra commentary):\n\n"
       << "SUMMARY: <1-2 sentences explaining the finding>\n"
       << "INDICATORS:\n"
       << "- <indicator 1>\n"
       << "- <indicator 2>\n"
       << "- <indicator 3 (if applicable)>\n"
       << "- <indicator 4 (if applicable)>\n"
       << "ACTIONS:\n"
       << "1. <recommended action 1>\n"
       << "2. <recommended action 2>\n"
       << "3. <recommended action 3>\n\n"
       << "RULES:\n"
       << "- SUMMARY must be 1-2 sentences only. No filler.\n"
       << "- INDICATORS: 2-4 bullet points. Each is one short phrase.\n"
       << "- ACTIONS: 2-3 numbered steps. Specific and actionable.\n"
       << "- Total response under 120 words. Plain text only.\n";

    if (classificationLevel == "Anomalous") {
        ss << "- For ACTIONS: recommend manual review first, not quarantine.\n";
    }
    ss << "\n";

    // ── File metadata ───────────────────────────────────────────────────
    ss << "FILE: " << fi.fileName().toStdString()
       << " (." << fi.suffix().toStdString() << ")\n"
       << "CLASSIFICATION: " << classificationLevel << "\n"
       << "SCORE: " << std::fixed << std::setprecision(3) << anomalyScore
       << " / 1.000 (threshold: 0.500)\n\n";

    // ── Condensed feature summary (only anomalous values) ───────────────
    if (static_cast<int>(features.size()) == kFeatureCount) {
        ss << "KEY FEATURES:\n";

        // Entropy
        ss << "  Entropy: " << std::setprecision(2) << features[1] << "/8.0";
        if (features[1] > 7.0f)      ss << " [VERY HIGH]";
        else if (features[1] > 5.5f) ss << " [ELEVATED]";
        ss << "\n";

        // File type
        if (features[2] > 0.5f) ss << "  Type: Executable\n";
        if (features[3] > 0.5f) ss << "  Type: Script\n";
        if (features[4] > 0.5f) ss << "  Type: DLL/Library\n";

        // Byte distribution (only if anomalous)
        if (features[7] > 0.3f)
            ss << "  High-byte ratio: " << std::setprecision(1) << (features[7]*100) << "% [ELEVATED]\n";

        // PE header (only if it's a PE file)
        if (features[16] > 0.5f) {
            ss << "  PE file: " << static_cast<int>(features[17] * 16) << " sections";
            if (features[18] > 0.875f) ss << ", max section entropy VERY HIGH";
            if (features[20] < 0.5f)   ss << ", entry point OUTSIDE code section";
            if (features[21] < 0.5f)   ss << ", NO debug info";
            if (features[25] > 0.5f)   ss << ", anomalous section names";
            if (features[27] > 0.3f)   ss << ", inflated virtual size";
            ss << "\n";
        }

        // Suspicious strings (only if present)
        if (features[32] > 0.1f)
            ss << "  Suspicious API refs: " << static_cast<int>(features[32] * 10) << "+\n";
        if (features[33] > 0.0f)
            ss << "  Embedded URLs: yes\n";
        if (features[34] > 0.0f)
            ss << "  Embedded IPs: yes\n";
        if (features[35] > 0.0f)
            ss << "  Registry paths: yes\n";
        if (features[36] > 0.0f)
            ss << "  Base64 strings: yes\n";
    }

    return ss.str();
}

// ============================================================================
// queryOllama  –  blocking HTTP POST to the local Ollama API
// ============================================================================
std::string LLMExplainer::queryOllama(const std::string& prompt) const
{
    QNetworkAccessManager mgr;
    QNetworkRequest req(QUrl(QString::fromStdString(m_config.ollamaUrl)));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QJsonObject payload;
    payload["model"]  = QString::fromStdString(m_config.model);
    payload["prompt"]  = QString::fromStdString(prompt);
    payload["stream"] = false;

    QJsonObject options;
    options["temperature"] = 0.2;
    options["num_predict"] = 256;
    options["top_p"]       = 0.9;
    options["repeat_penalty"] = 1.2;
    payload["options"] = options;

    QNetworkReply* reply = mgr.post(req, QJsonDocument(payload).toJson());

    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    timer.start(m_config.timeoutSecs * 1000);
    loop.exec();

    if (!reply->isFinished()) {
        reply->abort();
        reply->deleteLater();
        return "[LLM Explainer] Timeout: Ollama did not respond within "
               + std::to_string(m_config.timeoutSecs) + " seconds.";
    }

    if (reply->error() != QNetworkReply::NoError) {
        std::string err = "[LLM Explainer] Ollama error: "
                          + reply->errorString().toStdString();
        reply->deleteLater();
        return err;
    }

    QByteArray data = reply->readAll();
    reply->deleteLater();

    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (doc.isNull() || !doc.isObject()) {
        return "[LLM Explainer] Failed to parse Ollama response.";
    }

    QJsonObject obj = doc.object();
    if (obj.contains("response")) {
        return obj["response"].toString().toStdString();
    }

    return "[LLM Explainer] Unexpected Ollama response format.";
}

// ============================================================================
// explain  –  synchronous explanation (blocks calling thread)
//
// No debug output here — terminal output is handled exclusively by
// formatTerminalOutput() in FileScannerDetectors.cpp to avoid duplicates.
// ============================================================================
std::string LLMExplainer::explain(const std::string& filePath,
                                   const std::vector<float>& features,
                                   float anomalyScore,
                                   const std::string& classificationLevel) const
{
    std::string prompt = buildPrompt(filePath, features, anomalyScore,
                                     classificationLevel);

    std::string response = queryOllama(prompt);

    if (response.empty()) {
        return "[LLM Explainer] No response received from Ollama. "
               "Make sure Ollama is running (ollama serve) and the "
               + m_config.model + " model is pulled (ollama pull "
               + m_config.model + ").";
    }

    return response;
}

// ============================================================================
// explainAsync  –  fire-and-forget with callback
// ============================================================================
void LLMExplainer::explainAsync(const std::string& filePath,
                                 const std::vector<float>& features,
                                 float anomalyScore,
                                 ExplainCallback callback,
                                 const std::string& classificationLevel) const
{
    std::string promptCopy = buildPrompt(filePath, features, anomalyScore,
                                         classificationLevel);
    Config configCopy = m_config;

    std::thread([this, promptCopy, configCopy,
                 callback = std::move(callback)]() {

        std::string response = queryOllama(promptCopy);

        bool success = !response.empty() &&
                       response.find("[LLM Explainer]") == std::string::npos;

        if (response.empty()) {
            response = "[LLM Explainer] No response from Ollama.";
            success = false;
        }

        if (callback) {
            callback(response, success);
        }
    }).detach();
}
