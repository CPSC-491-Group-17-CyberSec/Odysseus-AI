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
    explicit FileScannerWorker(const QString& rootPath,
                               QAtomicInt*    cancelFlag,
                               QObject*       parent = nullptr);

public slots:
    void doScan();

signals:
    void scanningPath(const QString& path);
    void progressUpdated(int percent);
    void suspiciousFileFound(const SuspiciousFile& file);
    void scanFinished(int totalScanned, int suspiciousCount, int elapsedSeconds, qint64 bytesScanned);
    void scanError(const QString& message);

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

    void startScan(const QString& rootPath);
    void cancelScan();
    bool isRunning() const;

signals:
    void scanningPath(const QString& path);
    void progressUpdated(int percent);
    void suspiciousFileFound(const SuspiciousFile& file);
    void scanFinished(int totalScanned, int suspiciousCount, int elapsedSeconds, qint64 bytesScanned);
    void scanError(const QString& message);

private slots:
    void onThreadFinished();

private:
    QThread*           m_thread     = nullptr;
    FileScannerWorker* m_worker     = nullptr;
    QAtomicInt         m_cancelFlag { 0 };
};
