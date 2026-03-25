#pragma once

#include <QMainWindow>
#include <QString>
#include <QVector>

#include "../../core/FileScanner.h"
#include "../../db/ScanDatabase.h"   // for SuspiciousFile, ScanRecord
#include "../ScanTypeOverlay/ScanTypeOverlay.h"

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

    // ---- Database ----
    void onDbRecordSaved(qint64 scanId);
    void onCacheUpdateReady(const QVector<CacheEntry>& entries);

private:
    // -----------------------------------------------------------------------
    // Panel identity (only one right-side panel visible at a time)
    // -----------------------------------------------------------------------
    enum class ActivePanel { None, ThreatDetails, ScanResults, History, HistoryDetail };

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

    // Threat-details panel (existing, untouched)
    QFrame*  detailsPanel;
    QLabel*  detailsTitleLabel;
    QLabel*  detailsDescLabel;
    QLabel*  detailsAILabel;
    QLabel*  detailsMitreLabel;

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

    // CVE lookup
    QNetworkAccessManager*  m_nam           = nullptr;
    int                     m_cveQueryIndex = 0;      // next finding to look up

    // Track how many CVE queries are in flight
    int m_pendingCveQueries = 0;

    // Database
    ScanDatabase* m_db        = nullptr;
    int           m_scanCount = 0;   // used to trigger periodic cache pruning
};