#pragma once
// ============================================================================
// AlertsPage.h  –  Phase 4 + polish pass: full alert log (sidebar → Alerts).
//
// Layout:
//   [ Page header (title + subtitle) ]
//   [ Timeline strip — last EDR tick / new alerts ]
//   [ KPI strip (4 cards) ]
//   [ FilterBar ]
//   [ ─────────── 2-pane split ─────────── ]
//   [   Left: scrollable list of AlertRow widgets (zebra + grouped)   ]
//   [   Right: AlertDetailPanel (4 tabs + action buttons)              ]
//
// Read-only. Updates live via appendAlert() — MainWindow forwards every
// MonitoringService::alertRaised signal here. setLastTick() is called from
// MainWindow when MonitoringService::tickCompleted fires.
// ============================================================================

#include <QDateTime>
#include <QVector>
#include <QWidget>

#include "../../../include/edr/AlertTypes.h"

class QLabel;
class QFrame;
class QScrollArea;
class QVBoxLayout;
class QPushButton;
class QTimer;
class StatCard;
class FilterBar;
class AlertRow;
class AlertDetailPanel;

class AlertsPage : public QWidget {
  Q_OBJECT
 public:
  explicit AlertsPage(QWidget* parent = nullptr);

  /// Replace the list with a full snapshot (used on first show).
  void setAlerts(const QVector<EDR::Alert>& alerts);

  /// Append a single new alert (called from MainWindow when the
  /// MonitoringService emits alertRaised). Most-recent rendered first.
  void appendAlert(const EDR::Alert& alert);

  /// Mark an existing alert resolved (MonitoringService::alertResolved).
  /// Matches by alert.id; triggers a row + detail re-render.
  void markAlertResolved(const EDR::Alert& alert);

  /// Refresh an existing alert in place (MonitoringService::alertUpdated).
  /// Bumps lastSeen / ticksSeen / occurrenceCount on the matching id.
  void updateAlert(const EDR::Alert& alert);

  /// Wipe everything — used when EDR is disabled.
  void clear();

  /// Called from MainWindow when MonitoringService::tickCompleted fires.
  /// Updates the timeline strip ("last check N sec ago • K new alerts").
  void setLastTick(const QDateTime& when, int alertsThisTick);

  /// Toggle the "running but no first tick yet" loading hint.
  void setEdrRunning(bool running);

 private slots:
  void onRowClicked(int displayIndex);
  void onFiltersChanged();
  void onTimelineRefresh();
  void onOpenLocationRequested(const QString& path);

 private:
  // ── Internal type ──────────────────────────────────────────────────
  struct Group {
    EDR::Alert representative;   // shown in the row (most recent)
    int occurrences = 1;
    QVector<int> sourceIndices;  // indices into m_alerts (for detail)
  };

  void buildUi();
  void rebuildList();  // re-runs grouping + filtering, re-renders rows
  void refreshKpis();
  void refreshTimelineLabel();
  bool passesFilters(const EDR::Alert& a) const;
  QVector<Group> groupAndFilter() const;

  // ── Header ─────────────────────────────────────────────────────────
  QLabel* m_title = nullptr;
  QLabel* m_subtitle = nullptr;

  // ── Timeline strip ─────────────────────────────────────────────────
  QFrame* m_timeline = nullptr;
  QLabel* m_timelineDot = nullptr;
  QLabel* m_timelineText = nullptr;
  QTimer* m_timelineTick = nullptr;
  QDateTime m_lastTickAt;
  int m_lastTickNewAlerts = 0;
  bool m_edrRunning = false;
  bool m_haveFirstTick = false;

  // ── KPI strip ──────────────────────────────────────────────────────
  StatCard* m_kpiTotal = nullptr;
  StatCard* m_kpiCritical = nullptr;
  StatCard* m_kpiHigh = nullptr;
  StatCard* m_kpiRecent = nullptr;

  // ── Filter bar ─────────────────────────────────────────────────────
  FilterBar* m_filterBar = nullptr;

  // ── List + detail ──────────────────────────────────────────────────
  QScrollArea* m_listScroll = nullptr;
  QWidget* m_listHost = nullptr;
  QVBoxLayout* m_listLayout = nullptr;
  QLabel* m_emptyState = nullptr;
  QLabel* m_loadingState = nullptr;

  AlertDetailPanel* m_detail = nullptr;

  // Cached row widgets — rebuilt on every rebuildList() call. We
  // intentionally don't try to virtualize until row count > 200; for
  // typical EDR runs this is well below that threshold and a simple
  // recreate-all is fast enough.
  QVector<AlertRow*> m_rows;
  QVector<Group> m_currentGroups;  // mirrors row order; index = display
  int m_selectedRow = -1;
  QString m_selectedAlertId;       // survives re-grouping

  // Underlying data
  QVector<EDR::Alert> m_alerts;
};
