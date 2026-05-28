#pragma once

#include <QDialog>
#include <QString>

class QLabel;
class QPlainTextEdit;
class QProgressBar;
class QFormLayout;
class QVBoxLayout;

class ThreatCard : public QDialog {
  Q_OBJECT

 public:
  explicit ThreatCard(QWidget* parent = nullptr);

  void setSummary(const QString& summary);
  void setSeverity(int severity);
  void setRemediation(const QString& remediation);

  // ── New structured setters ──────────────────────────────────────────
  /// Set the severity level by name: "Low", "Medium", "High", "CRITICAL"
  void setSeverityLevel(const QString& level);

  /// Set the anomaly score (0.0–1.0) for the score bar
  void setAnomalyScore(float score, float threshold);

  /// Set the file name being analyzed
  void setFileName(const QString& name);

  /// Set key indicators as a list
  void setKeyIndicators(const QStringList& indicators);

  /// Set recommended actions as a list
  void setRecommendedActions(const QStringList& actions);

 private:
  void updateSeverityStyle(const QString& level);

  QLabel* titleLabel;
  QLabel* fileNameLabel;
  QLabel* severityLabel;
  QProgressBar* scoreBar;
  QLabel* scoreTextLabel;
  QPlainTextEdit* indicatorsBox;
  QPlainTextEdit* summaryBox;
  QPlainTextEdit* remediationBox;

  // Legacy compatibility
  QProgressBar* severityBar;
};
