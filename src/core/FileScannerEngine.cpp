// FileScannerEngine.cpp
// doScan() orchestrator and the UI-thread FileScanner controller.
//
// Architecture:
//   doScan() runs on the dedicated worker QThread and acts as the enumeration
//   producer.  It iterates the directory tree with QDirIterator, checks the
//   scan cache, and pushes uncached files onto a bounded work queue.
//
//   N hash-worker threads (QThread::create) consume that queue in parallel,
//   calling checkByHash() on each file.  Because checkByHash() is const and
//   only reads shared immutable data (m_hashDb, m_noHashExtensions, m_ctx),
//   no locking is needed inside it.
//
//   Signals (suspiciousFileFound, etc.) are emitted across thread boundaries
//   safely: all connections to FileScanner use Qt::QueuedConnection, and
//   Qt guarantees signal emission is thread-safe.
//
// Compiled with -O2.

#include <QDebug>
#include <QDir>
#include <QDirIterator>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QThread>
#include <atomic>

#include "FileScanner.h"

// ============================================================================
// shouldSkipDirectory
// ============================================================================
bool FileScannerWorker::shouldSkipDirectory(const QString& lowerDirPath) const {
  for (const QString& frag : m_skipDirFragments) {
    if (lowerDirPath.contains(frag))
      return true;
  }
  return false;
}

// ============================================================================
// doScan  –  enumeration producer + thread-pool coordinator
// ============================================================================
void FileScannerWorker::doScan() {
  QFileInfo rootInfo(m_rootPath);
  if (!rootInfo.exists() || !rootInfo.isDir()) {
    emit scanError(QString("Root path does not exist or is not a directory: %1").arg(m_rootPath));
    return;
  }

  QElapsedTimer wallTimer;
  wallTimer.start();

  // Reset shared accumulators (worker may theoretically be reused).
  m_totalScanned.storeRelaxed(0);
  m_suspiciousCount.storeRelaxed(0);
  m_bytesScanned.storeRelaxed(0);
  m_cacheHits.storeRelaxed(0);
  m_cacheMisses.storeRelaxed(0);
  m_enumDone.store(false, std::memory_order_relaxed);
  m_sharedCacheUpdates.clear();

  // ------------------------------------------------------------------
  // Launch N hash-worker threads.
  // We use min(idealThreadCount, 4) threads so we don't over-subscribe
  // on small machines, but fully exploit modern multi-core CPUs.
  // ------------------------------------------------------------------
  const int nWorkers = qBound(2, QThread::idealThreadCount(), 4);
  QVector<QThread*> hashThreads;
  hashThreads.reserve(nWorkers);
  for (int i = 0; i < nWorkers; ++i) {
    QThread* t = QThread::create([this]() { runHashWorker(); });
    t->start();
    hashThreads.append(t);
  }

  // ------------------------------------------------------------------
  // Enumeration phase (runs on this thread, i.e. the worker QThread).
  // ------------------------------------------------------------------
  int dirCount = 0;
  int lastProgress = 0;

  QDirIterator it(
      m_rootPath,
      QDir::Files | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot,
      QDirIterator::Subdirectories  // NO FollowSymlinks – avoids loops
  );

  // P1: cache per-directory state so toLower() + shouldSkipDirectory()
  // are called once per directory, not once per file.
  QString lastDir;
  QString lastLowerDir;
  bool lastShouldSkip = false;

  // Resume support: if m_resumeFromDir is set, skip everything before it.
  // Comparison is lexicographic on the absolute path – QDirIterator
  // visits in filesystem order which is typically alphabetical per level.
  bool pastResumePoint = m_resumeFromDir.isEmpty();

  while (it.hasNext()) {
    if (m_cancelFlag->loadRelaxed() != 0)
      break;

    it.next();
    const QFileInfo fi = it.fileInfo();

    const QString absPath = fi.absoluteFilePath();
    const QString dirPath = fi.absolutePath();

    // P1: recompute expensive per-directory work only on dir change.
    if (dirPath != lastDir) {
      lastDir = dirPath;
      lastLowerDir = dirPath.toLower();
      lastShouldSkip = shouldSkipDirectory(lastLowerDir);

      if (!lastShouldSkip) {
        ++dirCount;
        emit scanningPath(dirPath);

        // P8: asymptotic progress curve – avoids hard-coded target count.
        // Approaches 95% as dirCount grows; never stalls at 0% early on.
        const int newProgress = static_cast<int>(95.0 * dirCount / (dirCount + 400.0));
        if (newProgress != lastProgress) {
          lastProgress = newProgress;
          emit progressUpdated(newProgress);
        }
      }

      // P6: removed QThread::yieldCurrentThread() – the bounded work queue
      // (m_workHasSpace) already yields the enumerator when workers fall behind.

      // Once we reach or pass the stored resume directory, start scanning.
      if (!pastResumePoint && dirPath >= m_resumeFromDir)
        pastResumePoint = true;
    }

    if (lastShouldSkip || !pastResumePoint)
      continue;

    // Always count bytes so the storage label reflects the traversal scope.
    m_bytesScanned.fetchAndAddRelaxed(fi.size());

    const QString ext = fi.suffix().toLower();
    // P5: epoch ms avoids QDateTime::toString(Qt::ISODate) on every file.
    const qint64 lastModifiedMs = fi.lastModified().toMSecsSinceEpoch();

    // Cache hit: file unchanged since last scan – skip hashing/AI.
    // Key: path + lastModifiedMs + fileSize must all match.
    const auto cacheIt = m_scanCache.constFind(absPath);
    if (cacheIt != m_scanCache.constEnd() &&
        cacheIt.value().lastModifiedMs == lastModifiedMs  // P5: integer compare
        && cacheIt.value().fileSize == fi.size()) {
      m_totalScanned.fetchAndAddRelaxed(1);
      m_cacheHits.fetchAndAddRelaxed(1);

      // If the cached result was flagged, replay the finding.
      if (cacheIt.value().isFlagged) {
        const CacheEntry& ce = cacheIt.value();
        SuspiciousFile sf;
        sf.filePath = absPath;
        sf.fileName = fi.fileName();
        sf.reason = ce.reason;
        sf.category = ce.category;
        sf.sizeBytes = ce.fileSize;
        sf.lastModified = QDateTime::fromMSecsSinceEpoch(lastModifiedMs);
        sf.classificationLevel = ce.classificationLevel;
        sf.severityLevel = ce.severityLevel;
        sf.anomalyScore = ce.anomalyScore;
        sf.aiSummary = ce.aiSummary;
        sf.keyIndicators = ce.keyIndicators;
        sf.recommendedActions = ce.recommendedActions;
        sf.aiExplanation = ce.aiExplanation;
        sf.llmAvailable = ce.llmAvailable;
        // ── Phase 1 cached fields ──
        sf.sha256 = ce.sha256;
        sf.yaraMatches = ce.yaraMatches;
        sf.yaraFamily = ce.yaraFamily;
        sf.yaraSeverity = ce.yaraSeverity;
        sf.reputationFamily = ce.reputationFamily;
        sf.reputationSource = ce.reputationSource;
        sf.reputationPrevalence = ce.reputationPrevalence;
        sf.signingStatus = ce.signingStatus;
        sf.signerId = ce.signerId;
        sf.confidencePct = ce.confidencePct;

        emit suspiciousFileFound(sf);
        m_suspiciousCount.fetchAndAddRelaxed(1);
      }
      continue;
    }

    // Push to bounded work queue for a hash worker.
    {
      QMutexLocker lock(&m_workMutex);
      while (m_workQueue.size() >= kMaxQueueSize && m_cancelFlag->loadRelaxed() == 0) {
        // Queue full – yield until a worker drains some items.
        m_workHasSpace.wait(&m_workMutex);
      }
      if (m_cancelFlag->loadRelaxed() != 0)
        break;
      m_workQueue.enqueue({absPath, ext, fi.size(), lastModifiedMs});
      m_workHasItems.wakeOne();
    }
  }

  // ------------------------------------------------------------------
  // Signal enumeration complete; wake all waiting hash workers so they
  // can drain the remaining queue and exit.
  // ------------------------------------------------------------------
  {
    QMutexLocker lock(&m_workMutex);
    m_enumDone.store(true, std::memory_order_release);
    m_workHasItems.wakeAll();
  }

  // Wait for every hash worker to finish.
  for (QThread* t : hashThreads) {
    t->wait();
    delete t;
  }

  emit progressUpdated(100);
  const int elapsed = static_cast<int>(wallTimer.elapsed() / 1000);

  // Log cache performance summary.
  const int hits = m_cacheHits.loadRelaxed();
  const int misses = m_cacheMisses.loadRelaxed();
  const int total = hits + misses;
  qDebug() << "[CACHE] Scan complete."
           << "Cache hits:" << hits << "| Fresh scans:" << misses
           << "| Total files:" << m_totalScanned.loadRelaxed() << "| Hit rate:"
           << (total > 0 ? QString::number(100.0 * hits / total, 'f', 1) + "%" : "N/A");

  // Emit accumulated cache updates for DB persistence.
  if (!m_sharedCacheUpdates.isEmpty())
    emit cacheUpdateReady(m_sharedCacheUpdates);

  emit scanFinished(
      m_totalScanned.loadRelaxed(),
      m_suspiciousCount.loadRelaxed(),
      elapsed,
      m_bytesScanned.loadRelaxed());
}

// ============================================================================
// FileScanner  –  UI-thread controller
// ============================================================================
FileScanner::FileScanner(QObject* parent)
    : QObject(parent) {}

FileScanner::~FileScanner() {
  cancelScan();
}

bool FileScanner::isRunning() const {
  return m_thread && m_thread->isRunning();
}

void FileScanner::startScan(
    const QString& rootPath, QHash<QString, CacheEntry> scanCache, const QString& resumeFromDir) {
  if (m_thread && m_thread->isRunning())
    cancelScan();

  m_cancelFlag.storeRelaxed(0);

  m_thread = new QThread(this);
  m_worker = new FileScannerWorker(rootPath, &m_cancelFlag, std::move(scanCache), resumeFromDir);
  m_worker->moveToThread(m_thread);

  connect(m_thread, &QThread::finished, m_worker, &QObject::deleteLater);
  connect(m_thread, &QThread::finished, m_thread, &QObject::deleteLater);
  connect(m_thread, &QThread::finished, this, &FileScanner::onThreadFinished);
  connect(m_thread, &QThread::started, m_worker, &FileScannerWorker::doScan);

  connect(m_worker, &FileScannerWorker::scanFinished, m_thread, &QThread::quit);
  connect(m_worker, &FileScannerWorker::scanError, m_thread, &QThread::quit);

  connect(
      m_worker,
      &FileScannerWorker::scanningPath,
      this,
      &FileScanner::scanningPath,
      Qt::QueuedConnection);
  connect(
      m_worker,
      &FileScannerWorker::progressUpdated,
      this,
      &FileScanner::progressUpdated,
      Qt::QueuedConnection);
  connect(
      m_worker,
      &FileScannerWorker::suspiciousFileFound,
      this,
      &FileScanner::suspiciousFileFound,
      Qt::QueuedConnection);
  connect(
      m_worker,
      &FileScannerWorker::scanFinished,
      this,
      &FileScanner::scanFinished,
      Qt::QueuedConnection);
  connect(
      m_worker, &FileScannerWorker::scanError, this, &FileScanner::scanError, Qt::QueuedConnection);
  connect(
      m_worker,
      &FileScannerWorker::cacheUpdateReady,
      this,
      &FileScanner::cacheUpdateReady,
      Qt::QueuedConnection);

  m_thread->start();
}

void FileScanner::cancelScan() {
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

void FileScanner::onThreadFinished() {
  m_thread = nullptr;
  m_worker = nullptr;
}
