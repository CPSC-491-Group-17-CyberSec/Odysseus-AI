#pragma once
// ============================================================================
// ResultsPage.h  –  refactored Results tab matching the strict mockup.
//
// Layout:
//   ┌── Page ─────────────────────────────────────────────────────────────┐
//   │  Results                                       [Export Results]    │
//   │  Review and analyze detected threats                                 │
//   │                                                                      │
//   │  [ FilesScanned ] [ Suspicious ] [ NeedsReview ] [ AvgThreatScore ] │
//   │                                                                      │
//   │  [Search…]  [Severity ▾]  [Source ▾]                                │
//   │                                                                      │
//   │  ┌── Threat list ───────────┐ ┌── Detail panel (right) ────────┐  │
//   │  │ THREAT  SEV  CONF  SRC … │ │  CVE-XXX-YYYY                   │  │
//   │  │ ● row1                   │ │  Critical   Confidence 0.93     │  │
//   │  │ ● row2                   │ │  ───────────────────────────────│  │
//   │  │ ● row3                   │ │  File info  ▏ Why flagged?      │  │
//   │  │ …                        │ │  ▏ AI Summary  ▏ Indicators     │  │
//   │  └──────────────────────────┘ │  ▏ Recommended Actions          │  │
//   │                                │  [Quarantine]  [Delete] [Ignore]│  │
//   │                                └─────────────────────────────────┘  │
//   └──────────────────────────────────────────────────────────────────────┘
//
// Receives findings from MainWindow via addFinding() and refresh stat
// counters via setStats(). Emits exportRequested() when the Export
// button is clicked.
// ============================================================================

#include <QVector>
#include <QWidget>

#include "../../core/FileScanner.h"  // SuspiciousFile

class ThreatRow;
class DetailSection;
class StatCard;
class QLabel;
class QPushButton;
class QLineEdit;
class QComboBox;
class QVBoxLayout;
class QFrame;
class QProgressBar;
class QPlainTextEdit;

class ResultsPage : public QWidget {
  Q_OBJECT
 public:
  explicit ResultsPage(QWidget* parent = nullptr);

  /// Replace all current rows with the supplied finding set. Call this
  /// when MainWindow's m_findings changes wholesale (e.g. on history
  /// load) or after a scan completes.
  void setFindings(const QVector<SuspiciousFile>& findings);

  /// Append a single finding live (during an in-progress scan).
  void appendFinding(const SuspiciousFile& sf);

  /// Reset all rows and detail panel.
  void clear();

 signals:
  void exportRequested();

 private slots:
  void onRowClicked(int findingIndex);
  void onSearchChanged();
  void onFilterChanged();

  // Phase 5 — Response & Control Layer wiring.
  // Both slots use the currently-selected finding (m_selectedIndex) and
  // route through the global ResponseManager. They no-op if no finding
  // is selected.
  void onQuarantineClicked();
  void onIgnoreClicked();

 private:
  void buildUi();
  void rebuildVisibleRows();
  void recomputeStats();
  void populateDetail(const SuspiciousFile& sf);
  bool rowMatchesFilter(const SuspiciousFile& sf) const;
  static QString severityFromFinding(const SuspiciousFile& sf);

  // ── Header ─────────────────────────────────────────────────────────
  QLabel* m_title = nullptr;
  QLabel* m_subtitle = nullptr;
  QPushButton* m_exportBtn = nullptr;

  // ── KPI cards ──────────────────────────────────────────────────────
  StatCard* m_kpiFilesScanned = nullptr;
  StatCard* m_kpiSuspicious = nullptr;
  StatCard* m_kpiNeedsReview = nullptr;
  StatCard* m_kpiAvgScore = nullptr;

  // ── Filter row ─────────────────────────────────────────────────────
  QLineEdit* m_searchInput = nullptr;
  QComboBox* m_severityFilter = nullptr;
  QComboBox* m_sourceFilter = nullptr;

  // ── Threat list ────────────────────────────────────────────────────
  QFrame* m_listCard = nullptr;
  QVBoxLayout* m_rowsLayout = nullptr;
  QLabel* m_emptyState = nullptr;
  QLabel* m_resultsCount = nullptr;

  // ── Detail panel (right) ───────────────────────────────────────────
  QFrame* m_detailPanel = nullptr;
  QLabel* m_detailTitle = nullptr;
  QLabel* m_detailSeverity = nullptr;
  QLabel* m_detailConfText = nullptr;
  QProgressBar* m_detailConfBar = nullptr;
  QLabel* m_detailSource = nullptr;
  QLabel* m_detailDetected = nullptr;
  QLabel* m_detailFilePath = nullptr;
  QLabel* m_detailFileSize = nullptr;
  QLabel* m_detailSha256 = nullptr;
  DetailSection* m_secWhyFlagged = nullptr;
  DetailSection* m_secAiSummary = nullptr;
  DetailSection* m_secIndicators = nullptr;
  DetailSection* m_secActions = nullptr;
  QPushButton* m_btnQuarantine = nullptr;
  QPushButton* m_btnDelete = nullptr;
  QPushButton* m_btnIgnore = nullptr;
  QLabel* m_detailEmpty = nullptr;

  // ── State ──────────────────────────────────────────────────────────
  QVector<SuspiciousFile> m_findings;
  QVector<ThreatRow*> m_rows;
  int m_selectedIndex = -1;
};
