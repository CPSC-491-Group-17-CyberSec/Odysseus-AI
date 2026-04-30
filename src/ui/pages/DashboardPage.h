#pragma once
// ============================================================================
// DashboardPage.h  –  the new Phase 4 Dashboard layout
//
// Composes:
//   • Welcome header
//   • Four StatCards (System Status / Critical / Suspicious / Files Scanned)
//   • ScanTypeSelector + DonutChart row
//   • ActivityList + SecurityScoreCard row
//
// Data flow:
//   MainWindow calls refresh(findings, history, latestScan) whenever a
//   scan tick changes the visible numbers. The page itself holds NO
//   persistent state; every refresh fully repopulates the cards.
//
// Signals out to MainWindow:
//   • scanRequested(int type)  – Quick / Full / Custom (mirrors ScanTypeSelector)
//   • viewAllActivityClicked()
// ============================================================================

#include <QDateTime>
#include <QHash>
#include <QVector>
#include <QWidget>

#include "../../../include/edr/AlertTypes.h"       // EDR::Alert
#include "../../../include/edr/SecurityScoreEngine.h"
#include "../../../include/monitor/ProcessInfo.h"  // SystemSnapshot
#include "../../core/FileScanner.h"                // SuspiciousFile, ScanRecord

class StatCard;
class DonutChart;
class ScanTypeSelector;
class SecurityScoreCard;
class ActivityList;
class QLabel;

class DashboardPage : public QWidget {
  Q_OBJECT
 public:
  explicit DashboardPage(QWidget* parent = nullptr);

  /// Repopulate every card from the supplied state.
  /// `sysSnapshot` is optional — pass nullptr if the System Monitor hasn't
  /// produced a snapshot yet. When supplied, suspicious processes and
  /// integrity mismatches feed the security-score formula.
  void refresh(
      const QVector<SuspiciousFile>& findings,
      const QVector<ScanRecord>& history,
      bool scannerRunning,
      const SystemSnapshot* sysSnapshot = nullptr);

  /// Update the EDR-Lite status card. Called from MainWindow whenever
  /// the MonitoringService reports state changes (start/stop/tick).
  void setEdrStatus(bool enabled, const QDateTime& lastTick, int alertCount);

  /// Push a single EDR alert into the Recent Activity feed.
  void appendEdrAlert(const EDR::Alert& alert);

  /// Replace the security score with the risk-based report computed by
  /// SecurityScoreEngine over MonitoringService::activeAlerts(). When
  /// this is called the dashboard switches to the new "why this score"
  /// breakdown — older callers using just refresh() still get the
  /// legacy file-finding-based score.
  void setSecurityReport(const EDR::ScoreReport& report);

 signals:
  void scanRequested(int scanType);
  void viewAllActivityClicked();

 private:
  QLabel* m_welcomeTitle = nullptr;
  QLabel* m_welcomeSub = nullptr;
  StatCard* m_cardStatus = nullptr;
  StatCard* m_cardCritical = nullptr;
  StatCard* m_cardSuspicious = nullptr;
  StatCard* m_cardScanned = nullptr;
  StatCard* m_cardEdr = nullptr;  // Phase 4 — EDR-Lite
  ScanTypeSelector* m_scanSelector = nullptr;
  DonutChart* m_donut = nullptr;
  ActivityList* m_activity = nullptr;
  SecurityScoreCard* m_score = nullptr;
};
