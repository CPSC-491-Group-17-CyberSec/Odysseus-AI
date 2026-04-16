#pragma once

#include <QMainWindow>
#include <QString>
#include <QVector>

#include "../../core/FileScanner.h"
#include "../../db/ScanDatabase.h"   // for SuspiciousFile, ScanRecord
#include "../ScanTypeOverlay/ScanTypeOverlay.h"

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
    enum class ActivePanel { None, ThreatDetails, ScanResults, History, HistoryDetail };

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
};