#pragma once
// ============================================================================
// SystemStatusPanel.h  –  Phase 2: embedded UI panel for system monitoring
//
// Self-contained QWidget that MainWindow shows when the user clicks the
// "System Status" button. Owns no business logic — it just renders a
// SystemSnapshot supplied by SystemMonitor.
//
// Layout:
//   ┌─────────────────────────────────────────────┐
//   │ System Status            [Refresh] [Close]  │
//   │ Platform: macOS — last refresh: HH:MM:SS    │
//   │                                              │
//   │ Active Threats:    0                         │
//   │ Suspicious Procs:  3                         │
//   │ Persistence Items: 27                        │
//   │ ───────────────────────────────────────────── │
//   │ ⚠ Suspicious Processes (3)                  │
//   │   [list]                                     │
//   │ ───────────────────────────────────────────── │
//   │ 🔧 Persistence Items (27)                   │
//   │   [list]                                     │
//   └─────────────────────────────────────────────┘
// ============================================================================

#include <QFrame>

#include "../../../include/monitor/ProcessInfo.h"

class QLabel;
class QListWidget;
class QListWidgetItem;
class QPushButton;
class QProgressBar;

class SystemStatusPanel : public QFrame {
  Q_OBJECT
 public:
  explicit SystemStatusPanel(QWidget* parent = nullptr);

  /// Replace the rendered snapshot. Cheap; called from MainWindow whenever
  /// SystemMonitor emits snapshotReady.
  void setSnapshot(const SystemSnapshot& snap);

  /// Show/hide the per-section "loading" state. Called when the user
  /// clicks Refresh and the monitor is doing its work.
  void setRefreshing(bool refreshing);

 signals:
  /// Emitted when the user clicks the Refresh button.
  void refreshRequested();

  /// Emitted when the user clicks Close.
  void closeRequested();

 private slots:
  void onProcessRowClicked(QListWidgetItem* item);
  void onPersistenceRowClicked(QListWidgetItem* item);
  // Phase 3
  void onCrossViewRowClicked(QListWidgetItem* item);
  void onExtensionRowClicked(QListWidgetItem* item);
  void onIntegrityRowClicked(QListWidgetItem* item);

 private:
  void buildUi();

  // Header
  QPushButton* m_refreshBtn = nullptr;
  QPushButton* m_closeBtn = nullptr;
  QLabel* m_subTitle = nullptr;

  // KPI strip
  QLabel* m_kpiSuspicious = nullptr;
  QLabel* m_kpiPersistence = nullptr;
  QLabel* m_kpiTotalProcs = nullptr;
  QLabel* m_kpiPlatform = nullptr;

  // Sections
  QLabel* m_suspiciousHeader = nullptr;
  QListWidget* m_suspiciousList = nullptr;
  QLabel* m_persistenceHeader = nullptr;
  QListWidget* m_persistenceList = nullptr;

  // Phase 3 — rootkit awareness sections
  QLabel* m_kpiKernelExt = nullptr;  // KPI tile
  QLabel* m_kpiIntegrity = nullptr;  // KPI tile
  QLabel* m_crossViewHeader = nullptr;
  QListWidget* m_crossViewList = nullptr;
  QLabel* m_extensionsHeader = nullptr;
  QListWidget* m_extensionsList = nullptr;
  QLabel* m_integrityHeader = nullptr;
  QListWidget* m_integrityList = nullptr;

  // Detail box (shown when a row is clicked)
  QLabel* m_detailLabel = nullptr;

  // State
  SystemSnapshot m_snapshot;
};
