#pragma once

#include <QObject>
#include <QThread>
#include <QString>
#include <QVector>
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
    void scanFinished(int totalScanned, int suspiciousCount, int elapsedSeconds);
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

    // ----- Data -----
    QString     m_rootPath;
    QAtomicInt* m_cancelFlag;

    QVector<QString> m_highRiskExtensions;
    QVector<QString> m_suspiciousExtensions;
    QVector<QString> m_suspiciousNameFragments;
    QVector<QString> m_knownMalwareNames;
    QVector<QString> m_skipDirFragments;
    QVector<QString> m_trustedPathFragments;
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
    void scanFinished(int totalScanned, int suspiciousCount, int elapsedSeconds);
    void scanError(const QString& message);

private slots:
    void onThreadFinished();

private:
    QThread*           m_thread     = nullptr;
    FileScannerWorker* m_worker     = nullptr;
    QAtomicInt         m_cancelFlag { 0 };
};