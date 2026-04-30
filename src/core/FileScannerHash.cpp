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

#include <atomic>

#include "reputation/ReputationDB.h"
#include "reputation/CodeSigning.h"
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
        // P3: thread_local buffer — allocated once per worker thread, reused across files.
        static thread_local QByteArray buf(256 * 1024, Qt::Uninitialized);
        qint64 totalRead = 0;
        while (!f.atEnd()) {
            const qint64 n = f.read(buf.data(), buf.size());
            if (n < 0) { f.close(); return {}; }   // hard I/O error
            if (n == 0) break;
            hasher.addData(QByteArrayView(buf.constData(), static_cast<qsizetype>(n)));
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
                                     QString&       outCategory,
                                     QString&       outSha256) const
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

    // P2: always expose the computed hash so callers avoid recomputing it.
    outSha256 = hex;

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
    // P4: snapshot config + reputation handle once before the loop.
    // Both ScannerConfigStore::current() and odysseus_getReputationDB() acquire
    // a mutex; calling them per-file causes contention across 4 worker threads.
    const ScannerConfig cfg = ScannerConfigStore::current();
    ReputationDB* rep       = odysseus_getReputationDB();

    QVector<CacheEntry> localCache;
    localCache.reserve(256);

    auto flushLocalCache = [&]() {
        if (localCache.isEmpty()) return;
        QMutexLocker lock(&m_cacheMutex);
        m_sharedCacheUpdates.reserve(m_sharedCacheUpdates.size() + localCache.size());
        for (auto& e : localCache)
            m_sharedCacheUpdates.append(std::move(e));
        localCache.clear();
        localCache.reserve(256);
    };

    for (;;) {
        FileWorkItem item;

        {
            QMutexLocker lock(&m_workMutex);

            // Wait until there's work, enumeration is done, or scan cancelled.
            while (m_workQueue.isEmpty()
                   && !m_enumDone.load(std::memory_order_acquire)
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
        bool    flagged    = false;
        bool    aiOnlyFlag = false;   // true when only the AI pass triggered
        QString sha256;               // P2: populated by checkByHash even on miss
        SuspiciousFile sf;            // pre-allocate; downstream passes populate fields

        // --- Detection pass 1: known-hash lookup ---
        if (checkByHash(item.filePath, item.ext, item.fileSize, reason, category, sha256)) {
            flagged = true;
            sf.sha256              = sha256;   // already computed by checkByHash
            sf.classificationLevel = "Critical";
            sf.severityLevel       = "CRITICAL";
            sf.confidencePct       = 100.0f;   // hash hit = exact match
        }
        // --- Detection pass 2: YARA rule matching ---
        else if (checkByYara(item.filePath, item.fileSize, reason, category, &sf)) {
            flagged = true;
            // YARA pass already filled classificationLevel + confidencePct.
        }
        // --- Detection pass 3: AI anomaly scoring (fallback) ---
        else if (checkByAI(item.filePath, item.fileSize, reason, category, &sf)) {
            flagged    = true;
            aiOnlyFlag = true;  // track: only AI triggered, no hash/YARA corroboration
            // Map anomalyScore (0.0-1.0) → confidence percentage.
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
            // P5: convert epoch ms, not ISO string
            sf.lastModified = QDateTime::fromMSecsSinceEpoch(item.lastModifiedMs);

            // P2: reuse hash already computed by checkByHash on the hash pass;
            // only call hashFileForOdysseus for YARA/AI flagged files where
            // checkByHash didn't run or was skipped (exempt ext / network FS).
            if (sf.sha256.isEmpty()) {
                if (!sha256.isEmpty())
                    sf.sha256 = sha256;  // reuse from hash pass (no match, but computed)
                else if (!m_noHashExtensions.contains(item.ext) && !m_ctx.isNetworkFs)
                    sf.sha256 = hashFileForOdysseus(item.filePath, item.fileSize);
            }

            // ── Reputation DB enrichment ────────────────────────────────
            if (rep && !sf.sha256.isEmpty()) {
                ReputationRecord rr = rep->lookup(sf.sha256);
                if (rr.isKnown()) {
                    sf.reputationFamily     = rr.family;
                    sf.reputationSource     = rr.source;
                    sf.reputationPrevalence = rr.prevalence;
                    sf.signingStatus        = rr.signingStatus;
                    sf.signerId             = rr.signerId;
                    rep->recordSighting(sf.sha256);
                } else if (cfg.reputationAutoUpsert && !aiOnlyFlag) {
                    // Only persist YARA-confirmed findings into the reputation DB.
                    // AI-only detections are NOT upserted: the ML model's output
                    // is probabilistic, and adding it to the hash blocklist creates
                    // a self-reinforcing FP loop (AI guess → hash hit → Critical
                    // on every future scan, bypassing all threshold tuning).
                    ReputationRecord newRec;
                    newRec.sha256   = sf.sha256;
                    newRec.family   = !sf.yaraFamily.isEmpty()
                                          ? sf.yaraFamily
                                          : QStringLiteral("YARA-flagged");
                    newRec.source   = QStringLiteral("YARA/local");
                    newRec.severity = severityFromText(sf.severityLevel);
                    rep->upsert(newRec);
                    if (cfg.verboseLogging) {
                        qDebug().noquote()
                            << "[Reputation] upserted YARA-confirmed hash"
                            << sf.sha256.left(12) + "..."
                            << "(family:" << newRec.family << ")";
                    }
                }
            }

            // ── Code-signing check (gated by config) ──
            // Always run for flagged files when enabled. For AI-only findings,
            // a trusted signature downgrades or removes the finding entirely
            // to cut FPs on legitimately-signed system and commercial binaries.
            if (cfg.codeSigningEnabled && sf.signingStatus < 0) {
                CodeSigning::Result cs = CodeSigning::verifyFile(item.filePath);
                sf.signingStatus = CodeSigning::statusToInt(cs.status);
                sf.signerId      = cs.signerId;

                if (rep && cfg.reputationAutoUpsert && !sf.sha256.isEmpty()) {
                    ReputationRecord upd;
                    upd.sha256        = sf.sha256;
                    upd.signingStatus = sf.signingStatus;
                    upd.signerId      = sf.signerId;
                    rep->upsert(upd);
                }

                // For AI-only findings, apply trust-based downgrade:
                //   Trusted + Anomalous  → unflag entirely (signed software with weak signal)
                //   Trusted + Suspicious → downgrade to Anomalous (still surfaced, lower severity)
                //   Trusted + Critical   → unchanged (strong signal regardless of signature)
                //   Hash/YARA findings   → unchanged (concrete match overrides signing status)
                if (aiOnlyFlag && cs.status == CodeSigning::Status::SignedTrusted) {
                    if (sf.classificationLevel == "Anomalous") {
                        flagged = false;   // weak AI signal on trusted-signed file = FP
                    } else if (sf.classificationLevel == "Suspicious") {
                        sf.classificationLevel = "Anomalous";
                        sf.severityLevel       = "Low";
                        sf.confidencePct       = std::min(sf.confidencePct * 0.35f, 20.0f);
                        reason += "\n[Note: signed by trusted authority — severity downgraded]";
                    }
                }
            }

            if (!flagged) {
                // Unflagged by code-signing trust check — record as clean.
                CacheEntry ce;
                ce.filePath       = item.filePath;
                ce.lastModifiedMs = item.lastModifiedMs;
                ce.lastModified   = QDateTime::fromMSecsSinceEpoch(item.lastModifiedMs)
                                        .toString(Qt::ISODate);
                ce.fileSize       = item.fileSize;
                ce.isFlagged      = false;
                localCache.append(std::move(ce));
                if (localCache.size() >= 500) flushLocalCache();
                continue;
            }

            // Thread-safe: queued connection delivers to the UI thread.
            emit suspiciousFileFound(sf);
            m_suspiciousCount.fetchAndAddRelaxed(1);

            // Cache the flagged result so subsequent scans can replay it.
            CacheEntry ce;
            ce.filePath            = item.filePath;
            ce.lastModifiedMs      = item.lastModifiedMs;
            ce.lastModified        = QDateTime::fromMSecsSinceEpoch(item.lastModifiedMs)
                                         .toString(Qt::ISODate);
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
            ce.filePath       = item.filePath;
            ce.lastModifiedMs = item.lastModifiedMs;
            ce.lastModified   = QDateTime::fromMSecsSinceEpoch(item.lastModifiedMs)
                                    .toString(Qt::ISODate);
            ce.fileSize       = item.fileSize;
            ce.isFlagged      = false;
            localCache.append(std::move(ce));
        }

        // P7: flush local cache in batches to limit per-worker memory growth
        // and reduce the cost of the final merge lock.
        if (localCache.size() >= 500)
            flushLocalCache();
    }

    // Final flush – remaining entries not yet merged.
    flushLocalCache();
}
