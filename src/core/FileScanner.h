#pragma once

#include <QObject>
#include <QThread>
#include <QString>
#include <QVector>
#include <QSet>
#include <QHash>
#include <QDateTime>
#include <QAtomicInt>

// ---------------------------------------------------------------------------
// SuspiciousFile  –  one flagged file
// ---------------------------------------------------------------------------
struct SuspiciousFile
{
    QString   filePath;
    QString   fileName;
    QString   reason;
    QString   category;
    QString   cveId;          // filled in by CVE lookup, may be empty
    QString   cveSummary;     // short NVD description, may be empty
    QString   cveSeverity;    // "CRITICAL" / "HIGH" / "MEDIUM" / "LOW" / ""
    float     cveScore   = 0.0f;    // CVSS base score from NVD (0 = not found)
    qint64    sizeBytes  = 0;
    QDateTime lastModified;
};

// ---------------------------------------------------------------------------
// ScanRecord  –  everything from one completed scan, stored for history
// ---------------------------------------------------------------------------
struct ScanRecord
{
    QDateTime           timestamp;
    int                 totalScanned    = 0;
    int                 suspiciousCount = 0;
    int                 elapsedSeconds  = 0;
    QVector<SuspiciousFile> findings;
};

// ---------------------------------------------------------------------------
// CacheEntry  –  one row in the scan_cache table
// Passed into the worker as a pre-loaded QHash so the worker thread never
// touches the database directly.
// ---------------------------------------------------------------------------
struct CacheEntry
{
    QString filePath;
    QString lastModified;   // Qt::ISODate string – matches QFileInfo::lastModified()
};

// ---------------------------------------------------------------------------
// ScanContext  –  OS + filesystem profile detected at scan time
// ---------------------------------------------------------------------------
struct ScanContext
{
    bool runningOnLinux   = false;
    bool runningOnWindows = false;
    bool runningOnMac     = false;

    QString fsType;
    bool isWindowsFs  = false;
    bool isLinuxFs    = false;
    bool isMacFs      = false;
    bool isRemovable  = false;
    bool isNetworkFs  = false;  // used by checkByHash to skip high-latency I/O
    bool isReadOnly   = false;
};

// ---------------------------------------------------------------------------
// FileScannerWorker  –  runs on a dedicated QThread
// ---------------------------------------------------------------------------
class FileScannerWorker : public QObject
{
    Q_OBJECT

public:
    explicit FileScannerWorker(const QString&              rootPath,
                               QAtomicInt*                 cancelFlag,
                               QHash<QString, QString>     scanCache,
                               QObject*                    parent = nullptr);

public slots:
    void doScan();

signals:
    void scanningPath(const QString& path);
    void progressUpdated(int percent);
    void suspiciousFileFound(const SuspiciousFile& file);
    void scanFinished(int totalScanned, int suspiciousCount, int elapsedSeconds, qint64 bytesScanned);
    void scanError(const QString& message);
    // Emitted once at scan end – batch of newly-clean files to write to cache
    void cacheUpdateReady(const QVector<CacheEntry>& entries);

private:
    // ----- Scan loop helpers -----
    bool shouldSkipDirectory(const QString& lowerDirPath) const;

    // ----- Hash-based detection (sole detection method) -----
    bool checkByHash(const QString& filePath,
                     const QString& ext,
                     qint64         fileSize,
                     QString&       outReason,
                     QString&       outCategory) const;

    // ----- Setup -----
    static ScanContext              detectContext(const QString& rootPath);
    void                            buildFilterLists();
    static QHash<QString, QString>  loadHashDatabase();

    // ----- Data -----
    QString     m_rootPath;
    QAtomicInt* m_cancelFlag;
    ScanContext m_ctx;

    QVector<QString>        m_skipDirFragments;   // directories to skip entirely (performance)
    QSet<QString>           m_noHashExtensions;   // extensions exempt from hashing
    QHash<QString, QString> m_hashDb;             // sha256 hex → malware name

    // Incremental scan cache (path → lastModified ISO string)
    // Loaded once before the scan starts; never written from the worker thread.
    QHash<QString, QString> m_scanCache;
    // Accumulated clean-file entries to flush to DB after the scan.
    QVector<CacheEntry>     m_cacheUpdates;
};

// ---------------------------------------------------------------------------
// FileScanner  –  public controller (UI thread)
// ---------------------------------------------------------------------------
class FileScanner : public QObject
{
    Q_OBJECT

public:
    explicit FileScanner(QObject* parent = nullptr);
    ~FileScanner() override;

    void startScan(const QString& rootPath, QHash<QString, QString> scanCache = {});
    void cancelScan();
    bool isRunning() const;

signals:
    void scanningPath(const QString& path);
    void progressUpdated(int percent);
    void suspiciousFileFound(const SuspiciousFile& file);
    void scanFinished(int totalScanned, int suspiciousCount, int elapsedSeconds, qint64 bytesScanned);
    void scanError(const QString& message);
    void cacheUpdateReady(const QVector<CacheEntry>& entries);

private slots:
    void onThreadFinished();

private:
    QThread*           m_thread     = nullptr;
    FileScannerWorker* m_worker     = nullptr;
    QAtomicInt         m_cancelFlag { 0 };
};