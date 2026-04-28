#pragma once

#include <QMainWindow>
#include <QString>
#include <QVector>

#include "../../core/FileScanner.h"
#include "../../db/ScanDatabase.h"   // for SuspiciousFile, ScanRecord
#include "../ScanTypeOverlay/ScanTypeOverlay.h"
#include "../../../include/monitor/ProcessInfo.h"   // for SystemSnapshot

class SystemMonitor;
class SystemStatusPanel;

class LLMExplainer;

class QPushButton;
class QTableWidget;
class QTableWidgetItem;
class QLineEdit;
class QComboBox;
class QFrame;
class QLabel;
class QListWidget;
class QListWidgetItem;
class QProgressBar;
class QTimer;
class QNetworkAccessManager;
class QNetworkReply;
class QScrollArea;

class FileScanner;
class Sidebar;
class QStackedWidget;
class DashboardPage;
class ThreatDetailPanel;
class ResultsPage;
class ScanPage;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:
    // ---- Existing (logic unchanged) ----
    void onSimulateThreatClicked();
    void onFilterOrSearchChanged();
    void onThreatDoubleClicked(int row, int column);
    void onCloseDetailsClicked();

    // ---- Scan ----
    void onRunScanClicked();
    void onFullScanRequested();
    void onPartialScanRequested(const QString& path);
    void onResumeScanRequested();
    void onScanningPath(const QString& path);
    void onProgressUpdated(int percent);
    void onSuspiciousFileFound(const SuspiciousFile& file);
    void onScanFinished(int totalScanned, int suspiciousCount, int elapsedSeconds, qint64 bytesScanned);
    void onScanError(const QString& message);
    void onCloseScanResultsClicked();
    void onScanTimerTick();

    // ---- History ----
    void onHistoryClicked();
    void onHistoryItemClicked(QListWidgetItem* item);
    void onCloseHistoryClicked();

    // ---- System Status (Phase 2) ----
    void onSystemStatusClicked();
    void onSystemRefreshRequested();
    void onSystemCloseRequested();
    void onSystemSnapshotReady(const SystemSnapshot& snap);
    void onSystemSnapshotError(const QString& message);

    // ---- CVE lookup ----
    void onCveLookupReply(QNetworkReply* reply);

    // ---- On-demand LLM explanation ----
    void onLlmExplanationReady(int findingIndex, const QString& explanation, bool success);

    // ---- Database ----
    void onDbRecordSaved(qint64 scanId);
    void onCacheUpdateReady(const QVector<CacheEntry>& entries);

private:
    // -----------------------------------------------------------------------
    // Panel identity (only one right-side panel visible at a time)
    // -----------------------------------------------------------------------
    enum class ActivePanel { None, ThreatDetails, ScanResults, History, HistoryDetail, SystemStatus };

    // -----------------------------------------------------------------------
    // Scan mode – determines the storage denominator shown in the scan panel
    // -----------------------------------------------------------------------
    enum class ScanMode { Full, Partial, Resumed };

    void showPanel(ActivePanel panel);

    // -----------------------------------------------------------------------
    // UI helpers
    // -----------------------------------------------------------------------
    void setupUi();
    void loadTestData();
    void addThreatEntry(const QString& severity, const QString& name,
                        const QString& vendor,   const QString& date,
                        const QString& status);
    void startScanForPath(const QString& rootPath);

    // Inserts a row into threatTable for a scan finding (with CVE if found)
    void addScanFindingToTable(const SuspiciousFile& sf);

    // Kick off NVD API query for a single finding
    void lookupCveForFinding(int findingIndex);

    // Fire an async LLM explanation request for a finding
    void requestLlmExplanation(int findingIndex);

    // Refresh the detail panel LLM section (called after LLM completes)
    void refreshDetailLlmSection(const SuspiciousFile& sf);

    // Format elapsed seconds as MM:SS
    static QString formatElapsed(int secs);

    // Resize overlay when the window resizes
    void resizeEvent(QResizeEvent* event) override;

    // Populate historyDetailPanel from a ScanRecord
    void showHistoryDetail(const ScanRecord& record);

    // -----------------------------------------------------------------------
    // Existing widgets
    // -----------------------------------------------------------------------
    QPushButton*  runScanButton;
    QPushButton*  historyButton;      // NEW – top header
    QPushButton*  systemStatusButton; // Phase 2 – top header
    QTableWidget* threatTable;
    QLineEdit*    searchInput;
    QComboBox*    severityFilter;

    // Threat-details panel
    QFrame*  detailsPanel;
    QLabel*  detailsTitleLabel;
    QLabel*  detailsDescLabel;
    QLabel*  detailsAILabel;
    QLabel*  detailsMitreLabel;

    // -----------------------------------------------------------------------
    // AI Stats dashboard (replaces static stats)
    // -----------------------------------------------------------------------
    QLabel*  aiStatsTotalLabel;
    QLabel*  aiStatsCritLabel;
    QLabel*  aiStatsSuspLabel;
    QLabel*  aiStatsReviewLabel;
    QLabel*  aiStatsCleanLabel;
    QLabel*  aiStatsAvgScoreLabel;
    QLabel*  aiStatsModelLabel;
    QLabel*  aiStatsLlmLabel;           // LLM status indicator
    QFrame*  aiScoreFillBar;            // visual score indicator

    // -----------------------------------------------------------------------
    // Scan-results panel
    // -----------------------------------------------------------------------
    QFrame*       scanResultsPanel;
    QLabel*       scanStatusLabel;
    QLabel*       scanPathLabel;
    QProgressBar* scanProgressBar;
    QLabel*       scanElapsedLabel;
    QLabel*       scanStorageLabel;
    QListWidget*  scanResultsList;
    QLabel*       scanSummaryLabel;
    QPushButton*  closeScanButton;

    // -----------------------------------------------------------------------
    // History list panel
    // -----------------------------------------------------------------------
    QFrame*      historyPanel;
    QListWidget* historyList;
    QPushButton* closeHistoryButton;

    // -----------------------------------------------------------------------
    // History detail panel (shown when a history entry is clicked)
    // -----------------------------------------------------------------------
    QFrame*      historyDetailPanel;
    QLabel*      histDetailTitleLabel;
    QLabel*      histDetailSummaryLabel;
    QListWidget* histDetailFilesList;
    QPushButton* closeHistoryDetailButton;

    // -----------------------------------------------------------------------
    // Scan-type selection overlay
    // -----------------------------------------------------------------------
    ScanTypeOverlay*        m_scanOverlay   = nullptr;

    // Scanner engine
    // -----------------------------------------------------------------------
    FileScanner*            m_scanner       = nullptr;
    QVector<SuspiciousFile> m_findings;               // current scan
    QVector<ScanRecord>     m_history;                // all completed scans
    ActivePanel             m_activePanel   = ActivePanel::None;

    // Scan timer
    QTimer* m_scanTimer       = nullptr;
    int     m_elapsedSeconds  = 0;
    qint64  m_driveTotalBytes = 0;

    // Scan mode and active flag (used for storage-label logic)
    ScanMode m_scanMode   = ScanMode::Full;
    bool     m_scanActive = false;

    // CVE lookup
    QNetworkAccessManager*  m_nam           = nullptr;
    int                     m_cveQueryIndex = 0;      // next finding to look up

    // Track how many CVE queries are in flight
    int m_pendingCveQueries = 0;

    // On-demand LLM explanation
    LLMExplainer* m_llmExplainer      = nullptr;
    bool          m_llmChecked        = false;   // have we probed Ollama yet?
    bool          m_llmReachable      = false;   // is Ollama reachable?
    int           m_llmPendingIndex   = -1;      // finding index being queried (-1 = idle)
    int           m_detailFindingIdx  = -1;      // finding currently shown in detail panel

    // Database
    ScanDatabase* m_db        = nullptr;
    int           m_scanCount = 0;   // used to trigger periodic cache pruning

    // ---- Phase 2: System monitoring ----
    SystemMonitor*       m_sysmon          = nullptr;
    SystemStatusPanel*   m_systemPanel     = nullptr;

    // ---- Phase 4: Dashboard shell (sidebar + page stack) ----
    // Index values for m_pageStack: keep in sync with the order of addItem()
    // calls inside setupShell().
    enum NavPage {
        PageDashboard      = 0,
        PageScan           = 1,
        PageResults        = 2,
        PageSystemStatus   = 3,
        PageRootkit        = 4,
        PageThreatIntel    = 5,
        PageReports        = 6,
        PageSettings       = 7,
    };
    Sidebar*            m_sidebar         = nullptr;
    QStackedWidget*     m_pageStack       = nullptr;
    QWidget*            m_legacyDashWrap  = nullptr;   // hosts existing scan-progress UI on PageScan
    DashboardPage*      m_dashboardPage   = nullptr;   // new Phase 4 dashboard (page 0)
    ThreatDetailPanel*  m_threatDetail    = nullptr;   // Phase 4 Step 3 — right-slide detail panel
    ResultsPage*        m_resultsPage     = nullptr;   // refactored Results tab (page 2)
    ScanPage*           m_scanPage        = nullptr;   // refactored Scan tab (page 1)

    void setupShell();
    QWidget* makePlaceholderPage(const QString& title, const QString& subtitle);

    /// Stabilization B: hide the redundant legacy top-bar widgets (logo,
    /// title, History/SystemStatus/RunScan buttons — all duplicated by the
    /// sidebar) and re-skin the legacy threat table + search/filter so the
    /// "Results" page matches the new dark theme.
    void retireLegacyHeader();

    /// Push current findings/history into the new dashboard.
    /// No-op if the dashboard hasn't been built yet (during construction).
    void refreshDashboard();

private slots:
    void onSidebarPageRequested(int index);
    void onDashboardScanRequested(int scanType);
    void onDashboardViewAllActivity();
    void onThreatDetailCloseRequested();
    /// New ScanPage signals
    void onScanPageStartRequested(const QStringList& targets, int depth);
    void onScanPageExportLogs();
    void onScanPageViewAllRecent();
};