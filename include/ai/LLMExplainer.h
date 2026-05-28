#pragma once
// ============================================================================
// LLMExplainer.h  –  Local LLM integration via Ollama for threat explanation
//
// When a file is flagged as suspicious by the ML anomaly detector, this
// module sends the extracted feature data + anomaly score to a locally
// running Ollama instance (llama3 by default) and returns a human-readable
// explanation of:
//   1. Why the file was flagged
//   2. What the suspicious characteristics mean
//   3. Recommended next steps for the user
//
// Requires Ollama running locally:  brew install ollama && ollama serve
//
// Thread safety: each call creates its own QNetworkAccessManager for the
// HTTP request — safe to call from any thread.
// ============================================================================

#include <functional>
#include <string>
#include <vector>

class LLMExplainer {
 public:
  /// Configuration for the Ollama connection
  struct Config {
    std::string ollamaUrl = "http://localhost:11434/api/generate";
    std::string model = "llama3";
    int timeoutSecs = 60;
  };

  LLMExplainer();
  explicit LLMExplainer(const Config& config);
  ~LLMExplainer();

  // Non-copyable
  LLMExplainer(const LLMExplainer&) = delete;
  LLMExplainer& operator=(const LLMExplainer&) = delete;

  /// Check if Ollama is reachable (blocking call).
  bool isAvailable() const;

  /// Generate a synchronous explanation for a flagged file.
  /// @param filePath            Path to the suspicious file
  /// @param features            The 38-element feature vector
  /// @param anomalyScore        The ML model's anomaly score (0.0–1.0)
  /// @param classificationLevel "Anomalous", "Suspicious", or "CRITICAL"
  /// @return Human-readable explanation, or error message on failure
  std::string explain(
      const std::string& filePath,
      const std::vector<float>& features,
      float anomalyScore,
      const std::string& classificationLevel = "Suspicious") const;

  /// Async version: explanation delivered via callback on completion.
  /// The callback is invoked from a background thread.
  using ExplainCallback = std::function<void(const std::string& explanation, bool success)>;
  void explainAsync(
      const std::string& filePath,
      const std::vector<float>& features,
      float anomalyScore,
      ExplainCallback callback,
      const std::string& classificationLevel = "Suspicious") const;

  /// Build the prompt that gets sent to the LLM (exposed for testing)
  std::string buildPrompt(
      const std::string& filePath,
      const std::vector<float>& features,
      float anomalyScore,
      const std::string& classificationLevel = "Suspicious") const;

  /// Update configuration (e.g. change model or URL)
  void setConfig(const Config& config);
  Config config() const { return m_config; }

 private:
  Config m_config;

  /// Send a prompt to Ollama and return the response (blocking)
  std::string queryOllama(const std::string& prompt) const;
};
