#pragma once

#include <QObject>
#include <QThread>
#include <QString>
#include <QVector>
#include <QDateTime>
#include <QAtomicInt>
#include <QStorageInfo>

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
    // Running OS (compile-time)
    bool runningOnLinux   = false;
    bool runningOnWindows = false;
    bool runningOnMac     = false;

    // Filesystem of the scanned path (runtime, via QStorageInfo)
    QString fsType;             // "ext4", "ntfs", "apfs", etc. (lower-cased)
    bool isWindowsFs  = false;  // ntfs / fat / vfat / exfat / refs / fuseblk (ntfs-3g)
    bool isLinuxFs    = false;  // ext2/3/4, btrfs, xfs, zfs, f2fs, squashfs, etc.
    bool isMacFs      = false;  // apfs, hfs, hfsplus
    bool isRemovable  = false;  // vfat / exfat – typically USB sticks / SD cards
    bool isNetworkFs  = false;  // nfs, cifs, smb, fuse.sshfs, 9p, virtiofs
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
    void progressUpdated(int percent);                  // 0-99 while running
    void suspiciousFileFound(const SuspiciousFile& file);
    void scanFinished(int totalScanned, int suspiciousCount, int elapsedSeconds, qint64 bytesScanned);
    void scanError(const QString& message);

private:
    // ----- Detection helpers -----
    bool checkByNameAndExtension(const QString& fileName,
                                  const QString& lowerName,
                                  const QString& lowerPath,
                                  QString& outReason,
                                  QString& outCategory) const;

    bool checkByLocation(const QString& lowerPath,
                          const QString& ext,
                          QString& outReason,
                          QString& outCategory) const;

    bool checkByMagicBytes(const QString& filePath,
                            const QString& ext,
                            QString& outReason,
                            QString& outCategory) const;

    bool shouldSkipDirectory(const QString& lowerDirPath) const;
    bool isTrustedPath(const QString& lowerAbsPath) const;

    // Versioned soname: libfoo.so.1, libfoo.so.2.0.62, etc.
    static bool isVersionedSharedLib(const QString& lowerFileName, const QString& ext);

    // ----- Context detection & filter construction -----
    static ScanContext detectContext(const QString& rootPath);
    void buildFilterLists();

    // ----- Data -----
    QString     m_rootPath;
    QAtomicInt* m_cancelFlag;
    ScanContext m_ctx;

    QVector<QString> m_highRiskExtensions;
    QVector<QString> m_suspiciousExtensions;
    QVector<QString> m_suspiciousNameFragments;
    QVector<QString> m_knownMalwareNames;
    QVector<QString> m_skipDirFragments;
    QVector<QString> m_trustedPathFragments;
    QVector<QString> m_persistenceDirs;     // populated per-platform in buildFilterLists()
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
