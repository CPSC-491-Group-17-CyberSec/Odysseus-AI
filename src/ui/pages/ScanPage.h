#pragma once
// ============================================================================
// ScanPage.h  –  redesigned Scan tab matching the mockup.
//
// Three responsibilities:
//   • Gather scan targets (drag-drop + file/drive pickers)
//   • Configure scan engine options (model + detection toggles + depth)
//   • Surface recent-scan history and export entry point
//
// The Scan tab does NOT show scan results / threat tables (those live on
// the Results tab). When Start Scan is clicked, ScanPage emits
// scanRequested(targets, depth) — MainWindow routes it through the
// existing scan flow.
// ============================================================================

#include <QDateTime>
#include <QStringList>
#include <QVector>
#include <QWidget>

#include "../../core/FileScanner.h"  // ScanRecord

class StatCard;
class DropArea;
class QLabel;
class QPushButton;
class QListWidget;
class QComboBox;
class QCheckBox;
class QFrame;
class QVBoxLayout;

class ScanPage : public QWidget {
  Q_OBJECT
 public:
  enum ScanDepth { Quick = 0, Standard = 1, Deep = 2 };

  explicit ScanPage(QWidget* parent = nullptr);

  /// Refresh top KPI strip from MainWindow's data.
  /// `lastScan` may be invalid if there's no scan history yet.
  void setStats(
      const QDateTime& lastScan,
      int filesScanned,
      int threatsFound,
      bool protectedNow,
      bool scanning);

  /// Replace the Recent Scans list with the supplied history (newest-first).
  void setRecentScans(const QVector<ScanRecord>& history);

  /// Toggle Start-Scan button state when a scan is running.
  void setScanning(bool scanning);

 signals:
  /// User clicked Start Scan. `targets` may be empty (caller should
  /// fall back to a full system scan); `depth` follows ScanDepth.
  void scanRequested(const QStringList& targets, int depth);

  void exportLogsRequested();
  void viewAllRecentRequested();

 private slots:
  void onSelectFiles();
  void onSelectDrive();
  void onClearTargets();
  void onStartScan();
  void onTargetsDropped(const QStringList& paths);
  void onAdvancedSettingsClicked();

 private:
  void buildUi();

  QFrame* buildTargetsCard();
  QFrame* buildEngineCard();
  QFrame* buildSettingsCard();
  QFrame* buildRecentScansCard();

  void rebuildTargetList();
  void rebuildRecentScans();
  qint64 totalSelectedSize() const;
  static QString prettyBytes(qint64 b);

  // ── KPI strip ──────────────────────────────────────────────────────
  StatCard* m_kpiLastScan = nullptr;
  StatCard* m_kpiFilesScanned = nullptr;
  StatCard* m_kpiThreatsFound = nullptr;
  StatCard* m_kpiStatus = nullptr;

  // ── Scan Targets ──────────────────────────────────────────────────
  DropArea* m_dropArea = nullptr;
  QPushButton* m_btnSelectFiles = nullptr;
  QPushButton* m_btnSelectDrive = nullptr;
  QListWidget* m_targetList = nullptr;
  QLabel* m_targetsHeader = nullptr;
  QPushButton* m_btnClearAll = nullptr;
  QLabel* m_totalSize = nullptr;

  // ── Scan Engine ────────────────────────────────────────────────────
  QComboBox* m_aiModel = nullptr;
  QLabel* m_modelStatus = nullptr;
  QLabel* m_modelHelp = nullptr;
  QCheckBox* m_optRootkit = nullptr;
  QCheckBox* m_optMemory = nullptr;
  QCheckBox* m_optHeuristic = nullptr;
  QComboBox* m_scanDepth = nullptr;
  QLabel* m_depthHelp = nullptr;
  QPushButton* m_btnStart = nullptr;
  QLabel* m_startSubtitle = nullptr;

  // ── Scan Settings ──────────────────────────────────────────────────
  QPushButton* m_btnAdvanced = nullptr;

  // ── Recent Scans ──────────────────────────────────────────────────
  QListWidget* m_recentList = nullptr;
  QPushButton* m_btnExport = nullptr;
  QPushButton* m_btnViewAll = nullptr;

  // ── State ──────────────────────────────────────────────────────────
  QStringList m_targets;
  QVector<ScanRecord> m_history;
};
