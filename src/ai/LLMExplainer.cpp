// ============================================================================
// LLMExplainer.cpp  –  Ollama-based local LLM threat explanation
//
// Sends feature data from flagged files to a locally running Ollama
// instance and returns a human-readable analysis.  Falls back gracefully
// if Ollama is not running — the scanner continues to work without
// explanations.
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
    timer.start(5000);  // 5 second timeout for health check
    loop.exec();

    bool ok = reply->isFinished() &&
              reply->error() == QNetworkReply::NoError;
    reply->deleteLater();
    return ok;
}

// ============================================================================
// buildPrompt  –  construct the analysis prompt from features
// ============================================================================
std::string LLMExplainer::buildPrompt(const std::string& filePath,
                                       const std::vector<float>& features,
                                       float anomalyScore) const
{
    QFileInfo fi(QString::fromStdString(filePath));
    std::ostringstream ss;

    ss << "You are a cybersecurity analyst AI embedded in an antivirus scanner. "
       << "A file has been flagged as suspicious by our ML anomaly detection model. "
       << "Analyze the following feature data and provide:\n"
       << "1. A clear explanation of WHY this file is suspicious\n"
       << "2. What the key indicators mean in plain language\n"
       << "3. Recommended actions the user should take\n\n"
       << "Keep your response concise (under 200 words). "
       << "Do NOT use markdown formatting. Use plain text only.\n\n"
       << "=== FILE INFO ===\n"
       << "Filename: " << fi.fileName().toStdString() << "\n"
       << "Extension: " << fi.suffix().toStdString() << "\n"
       << "Anomaly Score: " << std::fixed << std::setprecision(3) << anomalyScore
       << " (threshold: 0.500, higher = more suspicious)\n\n";

    // Only include features if we have the right count
    if (static_cast<int>(features.size()) == kFeatureCount) {
        ss << "=== EXTRACTED FEATURES ===\n";

        // Pass 1: Metadata
        ss << "\n-- Metadata & Entropy --\n";
        ss << "File Size (log10 bytes): " << std::setprecision(2) << features[0] << "\n";
        ss << "Shannon Entropy: " << features[1] << " / 8.0 "
           << (features[1] > 7.0 ? "(HIGH - suggests encryption/compression)" :
               features[1] > 5.0 ? "(MODERATE)" : "(LOW - structured data)")
           << "\n";
        if (features[2] > 0.5f) ss << "File type: Executable (.exe)\n";
        if (features[3] > 0.5f) ss << "File type: Script\n";
        if (features[4] > 0.5f) ss << "File type: DLL\n";

        // Pass 2: Byte distribution (highlight anomalies only)
        ss << "\n-- Byte Distribution --\n";
        ss << "Null byte ratio: " << std::setprecision(4) << features[5] << "\n";
        ss << "Printable ASCII ratio: " << features[6] << "\n";
        ss << "High byte ratio (0x80-0xFF): " << features[7]
           << (features[7] > 0.4f ? " (HIGH - packed/encrypted content)" : "") << "\n";
        ss << "Byte mean: " << std::setprecision(1) << features[8]
           << ", StdDev: " << features[9] << "\n";
        ss << "Unique byte count (normalized): " << std::setprecision(3) << features[12] << "\n";

        // Pass 3: PE header (only if it's a PE file)
        if (features[16] > 0.5f) {
            ss << "\n-- PE Header Analysis --\n";
            ss << "PE sections: " << static_cast<int>(features[17]) << "\n";
            ss << "Max section entropy: " << std::setprecision(2) << features[18]
               << (features[18] > 7.0f ? " (VERY HIGH - likely packed/encrypted)" :
                   features[18] > 6.5f ? " (HIGH - suspicious)" : "")
               << "\n";
            ss << "Code section ratio: " << std::setprecision(3) << features[19] << "\n";
            ss << "Entry point in code section: " << (features[20] > 0.5f ? "YES" : "NO")
               << (!features[20] ? " (ANOMALOUS)" : "") << "\n";
            ss << "Has debug info: " << (features[21] > 0.5f ? "YES" : "NO")
               << (!features[21] ? " (unusual for legitimate software)" : "") << "\n";
            ss << "Import count: " << static_cast<int>(features[22]) << "\n";
            ss << "Export count: " << static_cast<int>(features[23]) << "\n";
            if (features[25] > 0.5f) ss << "WARNING: Anomalous section names detected\n";
            if (features[26] > 0.5f) ss << "WARNING: Suspicious PE timestamp\n";
            ss << "Virtual/Raw size ratio: " << std::setprecision(2) << features[27]
               << (features[27] > 5.0f ? " (VERY HIGH - unpacking indicator)" : "") << "\n";
        }

        // Pass 4: String analysis
        ss << "\n-- String Analysis --\n";
        ss << "Readable strings found: " << static_cast<int>(features[28]) << "\n";
        ss << "Suspicious API calls: " << static_cast<int>(features[32])
           << (features[32] > 3.0f ? " (HIGH - possible malicious behavior)" : "") << "\n";
        if (features[33] > 0.0f) ss << "URLs found: " << static_cast<int>(features[33]) << "\n";
        if (features[34] > 0.0f) ss << "IP addresses found: " << static_cast<int>(features[34]) << "\n";
        if (features[35] > 0.0f) ss << "Registry paths found: " << static_cast<int>(features[35]) << "\n";
        if (features[36] > 0.0f) ss << "Base64 strings found: " << static_cast<int>(features[36]) << "\n";
    }

    ss << "\n=== YOUR ANALYSIS ===\n";

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

    // Build the JSON payload
    QJsonObject payload;
    payload["model"]  = QString::fromStdString(m_config.model);
    payload["prompt"]  = QString::fromStdString(prompt);
    payload["stream"] = false;  // get the full response in one shot

    // Set generation parameters for concise output
    QJsonObject options;
    options["temperature"] = 0.3;     // low temperature for factual analysis
    options["num_predict"] = 512;     // limit output tokens
    payload["options"] = options;

    QNetworkReply* reply = mgr.post(req, QJsonDocument(payload).toJson());

    // Block until response or timeout
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
// ============================================================================
std::string LLMExplainer::explain(const std::string& filePath,
                                   const std::vector<float>& features,
                                   float anomalyScore) const
{
    std::string prompt = buildPrompt(filePath, features, anomalyScore);

    std::cout << "[LLMExplainer] Querying " << m_config.model
              << " for explanation of: " << filePath << std::endl;

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
                                 ExplainCallback callback) const
{
    // Capture copies of everything needed
    std::string promptCopy = buildPrompt(filePath, features, anomalyScore);
    Config configCopy = m_config;
    std::string filePathCopy = filePath;

    std::thread([this, promptCopy, configCopy, filePathCopy,
                 callback = std::move(callback)]() {
        std::cout << "[LLMExplainer] (async) Querying " << configCopy.model
                  << " for: " << filePathCopy << std::endl;

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
