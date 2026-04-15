// FileScannerHash.cpp
// SHA-256 hash database loading, hash-based malware detection, and the
// per-thread hash worker that consumes the work queue produced by doScan().
//
// runHashWorker() is called from N QThread::create threads.  It reads only
// const/atomic data on FileScannerWorker, so no global lock is held during
// the actual SHA-256 computation.
//
// Compiled with -O3: this is the most CPU/IO-intensive path in the scanner.

#include "FileScanner.h"

#include <QFile>
#include <QFileInfo>
#include <QCryptographicHash>
#include <QCoreApplication>
#include <QMutexLocker>
#include <QDateTime>

// ============================================================================
// loadHashDatabase  –  static, called once at worker construction.
// ============================================================================
QHash<QString, QString> FileScannerWorker::loadHashDatabase()
{
    QHash<QString, QString> db;

    const QString appDir = QCoreApplication::applicationDirPath();
    const QStringList candidates = {
        appDir + "/data/malware_hashes.txt",         // installed / cmake-copied
        appDir + "/../data/malware_hashes.txt",       // one level up
        appDir + "/../../data/malware_hashes.txt",    // two levels up (source root)
        appDir + "/../../../data/malware_hashes.txt", // three levels (nested build)
    };

    for (const QString& path : candidates) {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
            continue;

        while (!f.atEnd()) {
            const QString line = QString::fromUtf8(f.readLine()).trimmed();
            if (line.isEmpty() || line.startsWith('#'))
                continue;

            // Format: <sha256_hex>  <Malware Name / Description>
            const int spaceIdx = line.indexOf(' ');
            const QString hash = (spaceIdx > 0 ? line.left(spaceIdx) : line).toLower();
            const QString name = (spaceIdx > 0) ? line.mid(spaceIdx + 1).trimmed()
                                                 : QStringLiteral("Unknown Malware");

            if (hash.length() == 64)  // SHA-256 = 64 hex chars
                db.insert(hash, name);
        }
        break;  // loaded from first valid path
    }

    return db;
}

// ============================================================================
// checkByHash  –  SHA-256 the file, look it up in the loaded hash database.
//
// This method is const and reads only immutable members (m_hashDb,
// m_noHashExtensions, m_ctx), making it safe to call from multiple threads
// simultaneously with no locking.
//
// Uses memory-mapped I/O for files >= 256 KB (avoids user-space copy buffers;
// the OS page-cache handles prefetch efficiently on SSDs).  Falls back to
// chunked reads for smaller files or if mmap fails.
// ============================================================================
bool FileScannerWorker::checkByHash(const QString& filePath,
                                     const QString& ext,
                                     qint64         fileSize,
                                     QString&       outReason,
                                     QString&       outCategory) const
{
    if (m_noHashExtensions.contains(ext))
        return false;

    if (m_ctx.isNetworkFs)
        return false;

    constexpr qint64 maxHashBytes   = 200LL * 1024 * 1024;   // 200 MB hard cap
    constexpr qint64 mmapThreshold  = 256LL * 1024;           // 256 KB mmap crossover

    if (fileSize <= 0 || fileSize > maxHashBytes)
        return false;

    if (m_hashDb.isEmpty())
        return false;

    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly))
        return false;

    QCryptographicHash hasher(QCryptographicHash::Sha256);

    if (fileSize >= mmapThreshold) {
        // Memory-mapped path: no user-space copy; OS manages page faults.
        uchar* mapped = f.map(0, fileSize);
        if (mapped) {
            hasher.addData(QByteArrayView(mapped, static_cast<qsizetype>(fileSize)));
            f.unmap(mapped);
        } else {
            // mmap failed (e.g. tmpfs with no backing) – fall through to read.
            goto chunked_read;
        }
    } else {
        chunked_read:
        // Chunked-read path for small files or mmap fallback.
        char buf[65536];
        while (!f.atEnd()) {
            const qint64 n = f.read(buf, sizeof(buf));
            if (n <= 0) break;
            hasher.addData(QByteArrayView(buf, static_cast<qsizetype>(n)));
        }
    }
    f.close();

    const QString hex = QString::fromLatin1(hasher.result().toHex()).toLower();

    const auto it = m_hashDb.constFind(hex);
    if (it != m_hashDb.constEnd()) {
        outCategory = "Known Malware Hash";
        outReason   = QString("SHA-256 matches known malware sample: %1  [%2]")
                          .arg(it.value(), hex);
        return true;
    }

    return false;
}

// ============================================================================
// runHashWorker  –  consumer half of the producer-consumer pipeline.
//
// Called from N threads created by QThread::create inside doScan().
// Drains the work queue until both:
//   (a) the queue is empty, AND
//   (b) the enumeration thread has set m_enumDone = true
// or a cancellation is requested.
//
// Findings are emitted via Qt's queued-connection mechanism (thread-safe).
// Clean-file cache entries are accumulated locally and merged under a
// fine-grained mutex at the end to minimise contention.
// ============================================================================
void FileScannerWorker::runHashWorker()
{
    QVector<CacheEntry> localCache;

    for (;;) {
        FileWorkItem item;

        {
            QMutexLocker lock(&m_workMutex);

            // Wait until there's work, enumeration is done, or scan cancelled.
            while (m_workQueue.isEmpty()
                   && !m_enumDone
                   && m_cancelFlag->loadRelaxed() == 0)
            {
                m_workHasItems.wait(&m_workMutex);
            }

            // Exit conditions: queue drained after enumeration, or cancelled.
            if (m_workQueue.isEmpty())
                break;

            item = m_workQueue.dequeue();
            // Signal the producer that there's space again.
            m_workHasSpace.wakeOne();
        }

        if (m_cancelFlag->loadRelaxed() != 0)
            break;

        // Count every dequeued file as "scanned" and as a cache miss
        // (these items were not served from cache – they need full analysis).
        m_totalScanned.fetchAndAddRelaxed(1);
        m_cacheMisses.fetchAndAddRelaxed(1);

        QString reason, category;
        bool flagged = false;
        SuspiciousFile sf;  // pre-allocate; AI pass populates extra fields

        // --- Detection pass 1: known-hash lookup ---
        if (checkByHash(item.filePath, item.ext, item.fileSize, reason, category)) {
            flagged = true;
        }
        // --- Detection pass 2: AI anomaly scoring (fallback) ---
        else if (checkByAI(item.filePath, item.fileSize, reason, category, &sf)) {
            flagged = true;
        }

        if (flagged) {
            sf.filePath     = item.filePath;
            sf.fileName     = QFileInfo(item.filePath).fileName();
            sf.reason       = reason;
            sf.category     = category;
            sf.sizeBytes    = item.fileSize;
            sf.lastModified = QDateTime::fromString(item.lastModified, Qt::ISODate);

            // Thread-safe: queued connection delivers to the UI thread.
            emit suspiciousFileFound(sf);
            m_suspiciousCount.fetchAndAddRelaxed(1);

            // Cache the flagged result so subsequent scans can replay it.
            CacheEntry ce;
            ce.filePath            = item.filePath;
            ce.lastModified        = item.lastModified;
            ce.fileSize            = item.fileSize;
            ce.isFlagged           = true;
            ce.reason              = reason;
            ce.category            = category;
            ce.classificationLevel = sf.classificationLevel;
            ce.severityLevel       = sf.severityLevel;
            ce.anomalyScore        = sf.anomalyScore;
            ce.aiSummary           = sf.aiSummary;
            ce.keyIndicators       = sf.keyIndicators;
            ce.recommendedActions  = sf.recommendedActions;
            ce.aiExplanation       = sf.aiExplanation;
            ce.llmAvailable        = sf.llmAvailable;
            localCache.append(std::move(ce));
        } else {
            // File is clean – record for incremental-scan cache.
            CacheEntry ce;
            ce.filePath     = item.filePath;
            ce.lastModified = item.lastModified;
            ce.fileSize     = item.fileSize;
            ce.isFlagged    = false;
            localCache.append(std::move(ce));
        }
    }

    // Merge this worker's clean-file entries into the shared buffer.
    if (!localCache.isEmpty()) {
        QMutexLocker lock(&m_cacheMutex);
        m_sharedCacheUpdates.append(std::move(localCache));
    }
}
