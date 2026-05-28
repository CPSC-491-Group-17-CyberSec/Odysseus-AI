#pragma once
// ============================================================================
// AlertDetailPanel.h  –  tabbed alert detail (Overview / Why / Indicators /
// Details) plus the four non-destructive action buttons at the bottom.
//
// Action buttons (all read-only / non-destructive in this phase):
//   • Investigate    — disabled placeholder ("coming soon")
//   • Ignore         — disabled placeholder
//   • Open Location  — reveals the source path in Finder/Explorer
//   • Copy Details   — copies the alert's rawDetail to the clipboard
// ============================================================================

#include <QFrame>

#include "../../../include/edr/AlertTypes.h"

class QLabel;
class QPushButton;
class QTabWidget;
class QPlainTextEdit;
class QVBoxLayout;
class SeverityBadge;

class AlertDetailPanel : public QFrame {
  Q_OBJECT
 public:
  explicit AlertDetailPanel(QWidget* parent = nullptr);

  /// Show details for the supplied alert. `groupCount` ≥ 2 indicates
  /// this alert represents a deduplicated group; the Overview tab will
  /// surface the count + first/last seen.
  void setAlert(const EDR::Alert& alert, int groupCount = 1);

  /// Reset to "Select an alert" placeholder.
  void clear();

 signals:
  void openLocationRequested(const QString& path);
  void copyDetailsRequested(const QString& rawDetail);

 private slots:
  void onOpenLocationClicked();
  void onCopyDetailsClicked();

  // Phase 5 — Response & Control Layer wiring
  void onQuarantineClicked();
  void onIgnoreClicked();

 private:
  void buildUi();
  void setSectionsVisible(bool v);

  static QString trustText(int signingStatus);
  static const char* trustHex(int signingStatus);

  QLabel* m_emptyState = nullptr;

  // ── Header ─────────────────────────────────────────────────────────
  QLabel* m_titleLab = nullptr;
  SeverityBadge* m_severity = nullptr;
  QLabel* m_statusBadge = nullptr;  // Active / Resolved chip
  QLabel* m_categoryLab = nullptr;
  QLabel* m_timestampLab = nullptr;
  QLabel* m_groupBanner = nullptr;  // shown only for groups

  // ── Tabs ───────────────────────────────────────────────────────────
  QTabWidget* m_tabs = nullptr;

  // Overview
  QLabel* m_overSummary = nullptr;
  QLabel* m_overFirstSeen = nullptr;
  QLabel* m_overLastSeen = nullptr;
  QLabel* m_overSource = nullptr;
  QLabel* m_overProcess = nullptr;

  // Why Flagged
  QVBoxLayout* m_whyLayout = nullptr;
  QLabel* m_whyEmpty = nullptr;

  // Indicators
  QLabel* m_indTrust = nullptr;
  QLabel* m_indHashLabel = nullptr;
  QLabel* m_indHashVal = nullptr;
  QPushButton* m_indHashCopy = nullptr;
  QLabel* m_indReputation = nullptr;
  QLabel* m_indEmpty = nullptr;

  // Details
  QPlainTextEdit* m_detRaw = nullptr;

  // ── Actions ────────────────────────────────────────────────────────
  QPushButton* m_btnInvestigate = nullptr;
  QPushButton* m_btnIgnore = nullptr;
  QPushButton* m_btnQuarantine = nullptr;  // Phase 5 — file alerts only
  QPushButton* m_btnOpenLoc = nullptr;
  QPushButton* m_btnCopy = nullptr;

  EDR::Alert m_currentAlert;
};
