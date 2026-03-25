// FileScannerEngine.cpp
// Main scan loop (doScan) and the UI-thread FileScanner controller.
// Compiled with -O2.

#include "FileScanner.h"

#include <QDirIterator>
#include <QFileInfo>
#include <QDir>
#include <QElapsedTimer>
#include <QThread>

// ============================================================================
// shouldSkipDirectory
// ============================================================================
bool FileScannerWorker::shouldSkipDirectory(const QString& lowerDirPath) const
{
    for (const QString& frag : m_skipDirFragments) {
        if (lowerDirPath.contains(frag))
            return true;
    }
    return false;
}

// ============================================================================
// doScan  –  runs on the worker thread.
// Files are flagged only when their SHA-256 hash matches the loaded database.
// ============================================================================
void FileScannerWorker::doScan()
{
    QFileInfo rootInfo(m_rootPath);
    if (!rootInfo.exists() || !rootInfo.isDir()) {
        emit scanError(QString("Root path does not exist or is not a directory: %1")
                           .arg(m_rootPath));
        return;
    }

    QElapsedTimer wallTimer;
    wallTimer.start();

    int    totalScanned    = 0;
    int    suspiciousCount = 0;
    int    dirCount        = 0;
    qint64 totalBytes      = 0;

    const int targetDirs   = 500;
    int       lastProgress = 0;

    QDirIterator it(
        m_rootPath,
        QDir::Files | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot,
        QDirIterator::Subdirectories   // NO FollowSymlinks – avoids loops
    );

    QString lastDir;

    while (it.hasNext()) {
        if (m_cancelFlag->loadRelaxed() != 0)
            break;

        it.next();
        const QFileInfo fi = it.fileInfo();

        const QString absPath  = fi.absoluteFilePath();
        const QString dirPath  = fi.absolutePath();
        const QString lowerDir = dirPath.toLower();

        if (shouldSkipDirectory(lowerDir))
            continue;

        if (dirPath != lastDir) {
            lastDir = dirPath;
            ++dirCount;
            emit scanningPath(dirPath);

            const int newProgress = qMin(95, (dirCount * 95) / targetDirs);
            if (newProgress != lastProgress) {
                lastProgress = newProgress;
                emit progressUpdated(newProgress);
            }

            if (dirCount % 200 == 0)
                QThread::yieldCurrentThread();
        }

        ++totalScanned;
        totalBytes += fi.size();

        const QString ext = fi.suffix().toLower();
        QString reason, category;

        if (checkByHash(absPath, ext, fi.size(), reason, category)) {
            SuspiciousFile sf;
            sf.filePath     = absPath;
            sf.fileName     = fi.fileName();
            sf.reason       = reason;
            sf.category     = category;
            sf.sizeBytes    = fi.size();
            sf.lastModified = fi.lastModified();
            emit suspiciousFileFound(sf);
            ++suspiciousCount;
        }
    }

    emit progressUpdated(100);
    const int elapsed = static_cast<int>(wallTimer.elapsed() / 1000);
    emit scanFinished(totalScanned, suspiciousCount, elapsed, totalBytes);
}

// ============================================================================
// FileScanner  –  UI-thread controller
// ============================================================================
FileScanner::FileScanner(QObject* parent)
    : QObject(parent)
{}

FileScanner::~FileScanner()
{
    cancelScan();
}

bool FileScanner::isRunning() const
{
    return m_thread && m_thread->isRunning();
}

void FileScanner::startScan(const QString& rootPath)
{
    if (m_thread && m_thread->isRunning())
        cancelScan();

    m_cancelFlag.storeRelaxed(0);

    m_thread = new QThread(this);
    m_worker = new FileScannerWorker(rootPath, &m_cancelFlag);
    m_worker->moveToThread(m_thread);

    connect(m_thread, &QThread::finished, m_worker, &QObject::deleteLater);
    connect(m_thread, &QThread::finished, m_thread, &QObject::deleteLater);
    connect(m_thread, &QThread::finished, this,     &FileScanner::onThreadFinished);
    connect(m_thread, &QThread::started,  m_worker, &FileScannerWorker::doScan);

    connect(m_worker, &FileScannerWorker::scanFinished, m_thread, &QThread::quit);
    connect(m_worker, &FileScannerWorker::scanError,    m_thread, &QThread::quit);

    connect(m_worker, &FileScannerWorker::scanningPath,
            this,     &FileScanner::scanningPath,
            Qt::QueuedConnection);
    connect(m_worker, &FileScannerWorker::progressUpdated,
            this,     &FileScanner::progressUpdated,
            Qt::QueuedConnection);
    connect(m_worker, &FileScannerWorker::suspiciousFileFound,
            this,     &FileScanner::suspiciousFileFound,
            Qt::QueuedConnection);
    connect(m_worker, &FileScannerWorker::scanFinished,
            this,     &FileScanner::scanFinished,
            Qt::QueuedConnection);
    connect(m_worker, &FileScannerWorker::scanError,
            this,     &FileScanner::scanError,
            Qt::QueuedConnection);

    m_thread->start();
}

void FileScanner::cancelScan()
{
    if (!m_thread)
        return;

    m_cancelFlag.storeRelaxed(1);

    if (m_thread->isRunning()) {
        m_thread->quit();
        if (!m_thread->wait(4000)) {
            m_thread->terminate();
            m_thread->wait(1000);
        }
    }

    m_thread = nullptr;
    m_worker = nullptr;
}

void FileScanner::onThreadFinished()
{
    m_thread = nullptr;
    m_worker = nullptr;
}
