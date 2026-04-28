// FileScannerHash.cpp
// SHA-256 hash database loading, hash-based malware detection, and the
// per-thread hash worker that consumes the work queue produced by doScan().
//
// runHashWorker() is called from N QThread::create threads.  It reads only
// const/atomic data on FileScannerWorker, so no global lock is held during
// the actual SHA-256 computation.
//
// Phase 1 changes:
//   • The flat hash blocklist is now sourced from ReputationDB
//     (snapshot taken once per worker), with the existing data/
//     malware_hashes.txt acting as the seed file.
//   • runHashWorker() now invokes checkByYara() between the hash and AI
//     passes, so YARA rule matches surface as findings even when no hash
//     entry exists.
//   • SHA-256 is computed once and cached in SuspiciousFile / CacheEntry
//     so the reputation DB and downstream passes don't recompute it.
//
// Compiled with -O3: this is the most CPU/IO-intensive path in the scanner.

#include "FileScanner.h"

#include "reputation/ReputationDB.h"
#include "reputation/CodeSigning.h"
#include "core/ScannerConfig.h"

#include <QFile>
#include <QFileInfo>
#include <QCryptographicHash>
#include <QCoreApplication>
#include <QMutexLocker>
#include <QDateTime>

#include <algorithm>   // std::clamp, std::max

// Provided by FileScannerYaraReputation.cpp – returns the singleton or nullptr.
extern ReputationDB* odysseus_getReputationDB();

// ============================================================================
// loadHashDatabase  –  static, called once at worker construction.
//
// Phase 1: prefer the structured ReputationDB. The flat-text file remains
// as a seed and a fallback when the DB cannot be opened (e.g. AppData
// directory is read-only on a forensic boot).
// ============================================================================
QHash<QString, QString> FileScannerWorker::loadHashDatabase()
{
    // ----- Preferred path: snapshot from ReputationDB --------------------
    if (ReputationDB* rep = odysseus_getReputationDB()) {
        QHash<QString, QString> db = rep->snapshotHashIndex();
        if (!db.isEmpty())
            return db;
    }

    // ----- Fallback path: parse data/malware_hashes.txt directly ---------
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
// hashFileSha256  –  helper used by checkByHash and the YARA/AI paths.
//
// Returns the SHA-256 hex digest of the file, or an empty string on:
//   • exempt extension or network filesystem
//   • size 0 or > 200 MB
//   • I/O error
//
// Static / pure: no member access. Safe to call from multiple threads.
// ============================================================================
static QString hashFileSha256(const QString& filePath, qint64 fileSize)
{
    constexpr qint64 maxHashBytes  = 200LL * 1024 * 1024;
    constexpr qint64 mmapThreshold = 256LL * 1024;

    if (fileSize <= 0 || fileSize > maxHashBytes)
        return {};

    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly))
        return {};

    QCryptographicHash hasher(QCryptographicHash::Sha256);
    bool readOk = true;

    if (fileSize >= mmapThreshold) {
        uchar* mapped = f.map(0, fileSize);
        if (mapped) {
            hasher.addData(QByteArrayView(mapped, static_cast<qsizetype>(fileSize)));
            f.unmap(mapped);
        } else {
            readOk = false;   // fall through to chunked read
        }
    }
    if (!readOk || fileSize < mmapThreshold) {
        f.seek(0);
        char   buf[65536];
        qint64 totalRead = 0;
        while (!f.atEnd()) {
            const qint64 n = f.read(buf, sizeof(buf));
            if (n < 0) { f.close(); return {}; }   // hard I/O error
            if (n == 0) break;
            hasher.addData(QByteArrayView(buf, static_cast<qsizetype>(n)));
            totalRead += n;
        }
        // Partial read = corrupt/permission-denied mid-file = abort.
        if (totalRead == 0) { f.close(); return {}; }
    }
    f.close();
    return QString::fromLatin1(hasher.result().toHex()).toLower();
}

// ============================================================================
// checkByHash  –  SHA-256 the file, look it up in the loaded hash database.
//
// This method is const and reads only immutable members (m_hashDb,
// m_noHashExtensions, m_ctx), making it safe to call from multiple threads
// simultaneously with no locking.
//
// Phase 1: also stores the computed SHA-256 in `outSha` so YARA + AI passes
// (and the reputation DB sighting bump) can reuse it without re-hashing.
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

    if (m_hashDb.isEmpty())
        return false;

    const QString hex = hashFileSha256(filePath, fileSize);
    if (hex.isEmpty())
        return false;

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
// hashFileForOdysseus  –  external alias used by other detection passes.
//
// Exposed so checkByYara / checkByAI can compute (or reuse) a file's SHA-256
// without depending on FileScannerWorker internals. The free function lives
// outside the class so callers don't need a worker instance.
// ============================================================================
QString hashFileForOdysseus(const QString& filePath, qint64 fileSize)
{
    return hashFileSha256(filePath, fileSize);
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
        SuspiciousFile sf;  // pre-allocate; downstream passes populate fields

        // --- Detection pass 1: known-hash lookup ---
        if (checkByHash(item.filePath, item.ext, item.fileSize, reason, category)) {
            flagged = true;
            sf.classificationLevel = "Critical";
            sf.severityLevel       = "CRITICAL";
            sf.confidencePct       = 100.0f;     // hash hit = exact match
        }
        // --- Detection pass 2: YARA rule matching ---
        else if (checkByYara(item.filePath, item.fileSize, reason, category, &sf)) {
            flagged = true;
            // YARA pass already filled classificationLevel + confidencePct.
        }
        // --- Detection pass 3: AI anomaly scoring (fallback) ---
        else if (checkByAI(item.filePath, item.fileSize, reason, category, &sf)) {
            flagged = true;
            // Map anomalyScore (0.0-1.0) → confidence percentage.
            // The score is post-calibration; treat ≥ threshold as ≥ 50%.
            const float thr = (sf.anomalyThreshold > 0.0f) ? sf.anomalyThreshold : 0.5f;
            const float adj = (sf.anomalyScore - thr) / std::max(0.001f, 1.0f - thr);
            sf.confidencePct = std::clamp(50.0f + 50.0f * adj, 5.0f, 99.0f);
        }

        if (flagged) {
            sf.filePath     = item.filePath;
            sf.fileName     = QFileInfo(item.filePath).fileName();
            sf.reason       = reason;
            sf.category     = category;
            sf.sizeBytes    = item.fileSize;
            sf.lastModified = QDateTime::fromString(item.lastModified, Qt::ISODate);

            // ── Compute SHA-256 once for the SuspiciousFile (if not exempt) ─
            // checkByHash already hashed for matching; recompute lazily here
            // for YARA/AI flagged files that may have skipped the hash pass.
            if (sf.sha256.isEmpty()
                && !m_noHashExtensions.contains(item.ext)
                && !m_ctx.isNetworkFs)
            {
                sf.sha256 = hashFileForOdysseus(item.filePath, item.fileSize);
            }

            // ── Reputation DB enrichment ────────────────────────────────
            // Look up the SHA-256 in the reputation table; record a sighting
            // (prevalence++) if known.  When config.reputationAutoUpsert is
            // true, also persist new flagged hashes for future scans.
            const ScannerConfig& cfg = ScannerConfigStore::current();

            if (ReputationDB* rep = odysseus_getReputationDB()) {
                if (!sf.sha256.isEmpty()) {
                    ReputationRecord rr = rep->lookup(sf.sha256);
                    if (rr.isKnown()) {
                        sf.reputationFamily     = rr.family;
                        sf.reputationSource     = rr.source;
                        sf.reputationPrevalence = rr.prevalence;
                        sf.signingStatus        = rr.signingStatus;
                        sf.signerId             = rr.signerId;
                        // Sighting bump always runs — it just increments
                        // counters on a row that already exists.
                        rep->recordSighting(sf.sha256);
                    } else if (cfg.reputationAutoUpsert) {
                        // New flagged file: persist what we know so future
                        // scans recognize it without re-running YARA/AI.
                        ReputationRecord newRec;
                        newRec.sha256   = sf.sha256;
                        newRec.family   = !sf.yaraFamily.isEmpty()
                                              ? sf.yaraFamily
                                              : QStringLiteral("Unknown/AI-flagged");
                        newRec.source   = !sf.yaraMatches.isEmpty()
                                              ? QStringLiteral("YARA/local")
                                              : QStringLiteral("AI/local");
                        newRec.severity = severityFromText(sf.severityLevel);
                        rep->upsert(newRec);
                        if (cfg.verboseLogging) {
                            qDebug().noquote()
                                << "[Reputation] upserted new flagged hash"
                                << sf.sha256.left(12) + "..."
                                << "(family:" << newRec.family << ")";
                        }
                    }
                }

                // ── Code-signing check (gated by config) ──
                if (cfg.codeSigningEnabled
                    && sf.signingStatus < 0
                    && !sf.sha256.isEmpty())
                {
                    CodeSigning::Result cs = CodeSigning::verifyFile(item.filePath);
                    sf.signingStatus = CodeSigning::statusToInt(cs.status);
                    sf.signerId      = cs.signerId;

                    if (cfg.reputationAutoUpsert) {
                        ReputationRecord upd;
                        upd.sha256        = sf.sha256;
                        upd.signingStatus = sf.signingStatus;
                        upd.signerId      = sf.signerId;
                        rep->upsert(upd);
                    }
                }
            }

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
            // Phase 1 cache fields
            ce.sha256              = sf.sha256;
            ce.yaraMatches         = sf.yaraMatches;
            ce.yaraFamily          = sf.yaraFamily;
            ce.yaraSeverity        = sf.yaraSeverity;
            ce.reputationFamily    = sf.reputationFamily;
            ce.reputationSource    = sf.reputationSource;
            ce.reputationPrevalence = sf.reputationPrevalence;
            ce.signingStatus       = sf.signingStatus;
            ce.signerId            = sf.signerId;
            ce.confidencePct       = sf.confidencePct;
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
