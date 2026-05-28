#pragma once
// ============================================================================
// ThreatDetailPanel.h  –  Phase 4 Step 3: tabbed right-side details panel
//
// One panel, four tabs, populated from a SuspiciousFile (which already
// carries every field we need from Phase 1 + Phase 2 + Phase 3):
//
//   Overview     – AI summary, threat score bar, top recommended actions,
//                  hashes (SHA-256 / MD5)
//   AI Analysis  – full LLM explanation (Ollama), embedded AI commentary,
//                  model identity strings
//   Indicators   – keyIndicators[] from feature extractor, YARA rule names
//                  + family attribution
//   Details      – file path, sizes, signing status + signer ID, reputation
//                  family / source / prevalence, timestamps
//
// The panel itself is read-only. The Quarantine / Delete / Ignore buttons
// are deliberately rendered but DISABLED with a "Coming soon" tooltip per
// the redesign brief.
//
// Lifecycle:
//   • MainWindow owns one instance, parented into the shell's right column.
//   • Default visibility: hidden (zero width, no layout impact).
//   • setFile(sf) populates every tab. Caller then setVisible(true) to slide
//     it in. The user closes it via the X button — closeRequested signal
//     bubbles back so MainWindow hides the panel.
// ============================================================================

#include <QFrame>

#include "../../core/FileScanner.h"  // SuspiciousFile

class QLabel;
class QPushButton;
class QTabWidget;
class QPlainTextEdit;
class QListWidget;
class QProgressBar;

class ThreatDetailPanel : public QFrame {
  Q_OBJECT
 public:
  explicit ThreatDetailPanel(QWidget* parent = nullptr);

  /// Populate every tab from the supplied finding. Caller is expected to
  /// setVisible(true) after calling this.
  void setFile(const SuspiciousFile& sf);

  /// Wipe content + return to a neutral empty state.
  void clear();

 signals:
  void closeRequested();

  /// Action buttons (currently always disabled — placeholders for future
  /// Quarantine / Delete / Ignore wiring). Emitted only if we ever
  /// re-enable those buttons.
  void quarantineRequested(const QString& filePath);
  void deleteRequested(const QString& filePath);
  void ignoreRequested(const QString& filePath);

 private slots:
  void onCloseClicked();

 private:
  void buildUi();
  QWidget* buildOverviewTab();
  QWidget* buildAiAnalysisTab();
  QWidget* buildIndicatorsTab();
  QWidget* buildDetailsTab();

  void populateOverview(const SuspiciousFile& sf);
  void populateAiAnalysis(const SuspiciousFile& sf);
  void populateIndicators(const SuspiciousFile& sf);
  void populateDetails(const SuspiciousFile& sf);

  // ── Header ─────────────────────────────────────────────────────────
  QLabel* m_iconLabel = nullptr;
  QLabel* m_fileNameLabel = nullptr;
  QLabel* m_severityBadge = nullptr;
  QLabel* m_filePathLabel = nullptr;
  QLabel* m_fileMetaLabel = nullptr;
  QPushButton* m_closeBtn = nullptr;

  // ── Tabs ───────────────────────────────────────────────────────────
  QTabWidget* m_tabs = nullptr;

  // Overview
  QFrame* m_whyFlaggedCard = nullptr;  // prominent top-of-tab call-out
  QLabel* m_whyFlaggedLabel = nullptr;
  QLabel* m_aiSummaryLabel = nullptr;
  QProgressBar* m_scoreBar = nullptr;
  QLabel* m_scoreText = nullptr;
  QPlainTextEdit* m_overviewLlm = nullptr;
  QLabel* m_actionsLabel = nullptr;
  QLabel* m_sha256Compact = nullptr;

  // AI Analysis
  QPlainTextEdit* m_llmFull = nullptr;
  QLabel* m_modelInfoLabel = nullptr;
  QLabel* m_aiSummaryFull = nullptr;

  // Indicators
  QListWidget* m_indicatorsList = nullptr;
  QListWidget* m_yaraList = nullptr;
  QLabel* m_yaraFamilyLabel = nullptr;

  // Details
  QLabel* m_detPath = nullptr;
  QLabel* m_detSha256 = nullptr;
  QLabel* m_detSize = nullptr;
  QLabel* m_detModified = nullptr;
  QLabel* m_detSigning = nullptr;
  QLabel* m_detReputation = nullptr;
  QLabel* m_detClassification = nullptr;

  // ── Footer actions (disabled placeholders) ─────────────────────────
  QPushButton* m_quarantineBtn = nullptr;
  QPushButton* m_deleteBtn = nullptr;
  QPushButton* m_ignoreBtn = nullptr;

  QString m_currentPath;  // last-set file path; used by action signals
};
