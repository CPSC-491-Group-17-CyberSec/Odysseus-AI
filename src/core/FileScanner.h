#pragma once

#include <QAtomicInt>
#include <QDateTime>
#include <QHash>
#include <QMutex>
#include <QObject>
#include <QQueue>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QThread>
#include <QVector>
#include <QWaitCondition>
#include <atomic>

// Forward-declare for checkByAI / checkByYara parameter
struct SuspiciousFile;

// ---------------------------------------------------------------------------
// AI-based anomaly detector  –  called from runHashWorker() as a third pass
// after hash- and YARA-based detection.  Defined in FileScannerDetectors.cpp.
// ---------------------------------------------------------------------------
bool checkByAI(
    const QString& filePath,
    qint64 fileSize,
    QString& outReason,
    QString& outCategory,
    SuspiciousFile* outDetails = nullptr);

// ---------------------------------------------------------------------------
// YARA-based detector  –  called from runHashWorker() as a second pass after
// hash lookup.  Returns true if any YARA rule fires.  Populates outDetails
// with rule names, family attribution, and severity. Defined in
// FileScannerDetectors.cpp.
// ---------------------------------------------------------------------------
bool checkByYara(
    const QString& filePath,
    qint64 fileSize,
    QString& outReason,
    QString& outCategory,
    SuspiciousFile* outDetails = nullptr);

// ---------------------------------------------------------------------------
// SuspiciousFile  –  one flagged file
// ---------------------------------------------------------------------------
struct SuspiciousFile {
  QString filePath;
  QString fileName;
  QString reason;
  QString category;
  QString cveId;          // filled in by CVE lookup, may be empty
  QString cveSummary;     // short NVD description, may be empty
  QString cveSeverity;    // "CRITICAL" / "HIGH" / "MEDIUM" / "LOW" / ""
  float cveScore = 0.0f;  // CVSS base score from NVD (0 = not found)
  qint64 sizeBytes = 0;
  QDateTime lastModified;
  QString aiExplanation;      // LLM-generated threat explanation (Ollama/Llama3, may be empty)
  bool llmAvailable = false;  // true if Ollama responded for this finding

  // ── Embedded AI anomaly detection metadata (populated by checkByAI) ─
  float anomalyScore = 0.0f;       // ML model output (0.0–1.0)
  float anomalyThreshold = 0.5f;   // effective threshold used
  QString severityLevel;           // "Low" / "Medium" / "High" / "CRITICAL"
  QString classificationLevel;     // "Anomalous" / "Suspicious" / "CRITICAL"
  QStringList keyIndicators;       // top contributing factors (embedded AI)
  QString aiSummary;               // embedded AI concise explanation
  QStringList recommendedActions;  // embedded AI action items

  // ── Phase 1: SHA-256, YARA, reputation, code signing ────────────────
  QString sha256;                // file SHA-256 (filled if computed)
  QStringList yaraMatches;       // names of YARA rules that fired
  QString yaraFamily;            // first family= meta tag from a match
  QString yaraSeverity;          // worst severity= across fired rules
  QString reputationFamily;      // family from reputation DB (if known)
  QString reputationSource;      // where the reputation row came from
  int reputationPrevalence = 0;  // times we've seen this hash on this host
  int signingStatus = -1;        // CodeSigning::Status as int
  QString signerId;              // Authority / Team-ID / package name
  float confidencePct = 0.0f;    // 0-100 derived from anomalyScore + indicators
};

// ---------------------------------------------------------------------------
// ScanRecord  –  everything from one completed scan, stored for history
// ---------------------------------------------------------------------------
struct ScanRecord {
  QDateTime timestamp;
  int totalScanned = 0;
  int suspiciousCount = 0;  // total flagged (all non-Clean)
  int criticalCount = 0;    // Critical verdict
  int suspiciousOnly = 0;   // Suspicious verdict (not Critical)
  int reviewCount = 0;      // Anomalous / Needs Review
  int elapsedSeconds = 0;
  QVector<SuspiciousFile> findings;
};

// ---------------------------------------------------------------------------
// CacheEntry  –  one row in the scan_cache table
// Passed into the worker as a pre-loaded QHash so the worker thread never
// touches the database directly.
//
// Extended (v2): stores both clean and flagged file results so subsequent
// scans can skip re-scanning unchanged files entirely.
// ---------------------------------------------------------------------------
struct CacheEntry {
  QString filePath;
  QString lastModified;       // Qt::ISODate string (for DB persistence)
  qint64 lastModifiedMs = 0;  // epoch ms (derived on load; used for fast comparison)
  qint64 fileSize = 0;
  bool isFlagged = false;

  // ── Flagged-file metadata (empty for clean files) ──────────────────
  QString reason;
  QString category;
  QString classificationLevel;  // "Anomalous" / "Suspicious" / "Critical"
  QString severityLevel;
  float anomalyScore = 0.0f;
  QString aiSummary;
  QStringList keyIndicators;
  QStringList recommendedActions;
  QString aiExplanation;  // LLM explanation (may be empty)
  bool llmAvailable = false;

  // ── Phase 1 cache fields (mirror SuspiciousFile) ───────────────────
  QString sha256;
  QStringList yaraMatches;
  QString yaraFamily;
  QString yaraSeverity;
  QString reputationFamily;
  QString reputationSource;
  int reputationPrevalence = 0;
  int signingStatus = -1;
  QString signerId;
  float confidencePct = 0.0f;
};

// ---------------------------------------------------------------------------
// ScanContext  –  OS + filesystem profile detected at scan time
// ---------------------------------------------------------------------------
struct ScanContext {
  bool runningOnLinux = false;
  bool runningOnWindows = false;
  bool runningOnMac = false;

  QString fsType;
  bool isWindowsFs = false;
  bool isLinuxFs = false;
  bool isMacFs = false;
  bool isRemovable = false;
  bool isNetworkFs = false;  // used by checkByHash to skip high-latency I/O
  bool isReadOnly = false;
};

// ---------------------------------------------------------------------------
// FileWorkItem  –  a file queued for SHA-256 hashing by a worker thread
// ---------------------------------------------------------------------------
struct FileWorkItem {
  QString filePath;
  QString ext;
  qint64 fileSize;
  qint64 lastModifiedMs;  // epoch ms – avoids QDateTime::toString() per file
};

// ---------------------------------------------------------------------------
// FileScannerWorker  –  runs on a dedicated QThread
// ---------------------------------------------------------------------------
class FileScannerWorker : public QObject {
  Q_OBJECT

 public:
  explicit FileScannerWorker(
      const QString& rootPath,
      QAtomicInt* cancelFlag,
      QHash<QString, CacheEntry> scanCache,
      const QString& resumeFromDir = {},
      QObject* parent = nullptr);

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

  // ----- Hash-based detection -----
  bool checkByHash(
      const QString& filePath,
      const QString& ext,
      qint64 fileSize,
      QString& outReason,
      QString& outCategory,
      QString& outSha256) const;  // always populated when hash is computed

  // ----- Hash worker (called by N QThread::create threads) -----
  void runHashWorker();

  // ----- Setup -----
  static ScanContext detectContext(const QString& rootPath);
  void buildFilterLists();
  static QHash<QString, QString> loadHashDatabase();

  // ----- Static config -----
  static constexpr int kMaxQueueSize = 2000;  // max pending work items

  // ----- Core data -----
  QString m_rootPath;
  QAtomicInt* m_cancelFlag;
  QString m_resumeFromDir;  // if set, skip dirs before this path
  ScanContext m_ctx;

  QVector<QString> m_skipDirFragments;
  QSet<QString> m_noHashExtensions;
  QHash<QString, QString> m_hashDb;  // sha256 hex → malware name

  // Incremental scan cache (path → CacheEntry with result metadata)
  QHash<QString, CacheEntry> m_scanCache;

  // ----- Multi-thread work queue -----
  // Enumeration thread produces FileWorkItems; N hash workers consume them.
  QMutex m_workMutex;
  QWaitCondition m_workHasItems;        // wakes consumers when queue gains items
  QWaitCondition m_workHasSpace;        // wakes producer when queue drains below max
  QQueue<FileWorkItem> m_workQueue;
  std::atomic<bool> m_enumDone{false};  // S1: atomic — read by worker threads without lock

  // ----- Shared accumulators (written by hash workers) -----
  QAtomicInt m_totalScanned{0};
  QAtomicInt m_suspiciousCount{0};
  QAtomicInteger<qint64> m_bytesScanned{0};
  QAtomicInt m_cacheHits{0};
  QAtomicInt m_cacheMisses{0};

  // Cache updates buffer – written by workers, flushed after all workers join
  QMutex m_cacheMutex;
  QVector<CacheEntry> m_sharedCacheUpdates;
};

// ---------------------------------------------------------------------------
// FileScanner  –  public controller (UI thread)
// ---------------------------------------------------------------------------
class FileScanner : public QObject {
  Q_OBJECT

 public:
  explicit FileScanner(QObject* parent = nullptr);
  ~FileScanner() override;

  void startScan(
      const QString& rootPath,
      QHash<QString, CacheEntry> scanCache = {},
      const QString& resumeFromDir = {});
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
  QThread* m_thread = nullptr;
  FileScannerWorker* m_worker = nullptr;
  QAtomicInt m_cancelFlag{0};
};
