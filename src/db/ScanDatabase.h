#pragma once

// ============================================================================
// ScanDatabase  –  local SQLite persistence for scan records
//
// Design decisions (per project report section 2.5):
//   • Single SQLite file stored in the platform-appropriate app-data directory.
//   • All DB writes go through a dedicated writer thread (m_writerThread) with
//     a lock-free queue, keeping file I/O off the UI thread.
//   • Reads happen synchronously on the caller's thread (always the UI thread).
//   • Cross-platform: uses QStandardPaths for the database location so the
//     path is correct on Windows (%APPDATA%), macOS (~/.config or ~/Library),
//     and Linux (~/.local/share).
//   • Schema stores at minimum: file_path, file_size, last_modified,
//     sha256_hash, scan_status  (plus the parent scan record).
// ============================================================================

#include <QDateTime>
#include <QHash>
#include <QMutex>
#include <QObject>
#include <QQueue>
#include <QString>
#include <QThread>
#include <QVector>
#include <QWaitCondition>
#include <functional>

#include "../core/FileScanner.h"  // SuspiciousFile, ScanRecord

// Forward-declare the opaque SQLite handle so callers never need sqlite3.h
struct sqlite3;

// ---------------------------------------------------------------------------
// DatabaseWriteTask  –  a closure enqueued for the writer thread
// ---------------------------------------------------------------------------
using DatabaseWriteTask = std::function<void(sqlite3*)>;

// ---------------------------------------------------------------------------
// ScanDatabase  –  public API (UI thread)
// ---------------------------------------------------------------------------
class ScanDatabase : public QObject {
  Q_OBJECT

 public:
  // -------------------------------------------------------------------------
  // Construction / destruction
  // -------------------------------------------------------------------------
  explicit ScanDatabase(QObject* parent = nullptr);
  ~ScanDatabase() override;

  // -------------------------------------------------------------------------
  // Async write operations  (safe to call from any thread)
  // -------------------------------------------------------------------------

  // Persist a completed ScanRecord (header row + all findings).
  // Non-blocking: enqueues the work and returns immediately.
  void saveScanRecord(const ScanRecord& record);

  // -------------------------------------------------------------------------
  // Synchronous read operations  (UI thread only)
  // -------------------------------------------------------------------------

  // Load all ScanRecords from the database, newest-first.
  QVector<ScanRecord> loadAllScanRecords() const;

  // Load just the N most-recent scan headers (no findings) – fast overview.
  QVector<ScanRecord> loadRecentScanHeaders(int n = 50) const;

  // Load the entire scan cache into memory as path → CacheEntry.
  // Call this on the UI thread before starting a scan; pass the result
  // to FileScanner::startScan() so the worker can do cache lookups.
  // Extended (v2): includes flagged-file metadata so cached findings
  // can be replayed without re-scanning.
  QHash<QString, CacheEntry> loadScanCache() const;

  // Persist a batch of newly-clean file entries into the scan_cache table.
  // Non-blocking: enqueues the work for the writer thread.
  void flushScanCache(const QVector<CacheEntry>& entries);

  // Remove entries from scan_cache for files that no longer exist on disk.
  // Call occasionally (e.g. after every 5th scan) to prevent stale growth.
  void pruneStaleCache();

  // Last scan root path (used by "Scan from Last Point").
  // Stored in the scan_state key-value table.
  QString loadLastScanRoot() const;
  void saveLastScanRoot(const QString& rootPath);  // async

  // Full path to the SQLite file (useful for diagnostics).
  QString databasePath() const { return m_dbPath; }

  // Clears all historical scans, findings, and cached items
  bool clearAllData();

 signals:
  // Emitted on the UI thread once a saveScanRecord() write has committed.
  void recordSaved(qint64 scanId);

  // Emitted if any database operation fails.
  void databaseError(const QString& message);

 private:
  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------
  bool openDatabase(sqlite3** db, const QString& path) const;
  bool createSchema(sqlite3* db);

  // Enqueue a task for the writer thread.
  void enqueueWrite(DatabaseWriteTask task);

  // Compute SHA-256 hash of a file (cross-platform, Qt-only, no OpenSSL dep).
  // Returns empty string on failure.
  static QString computeSha256(const QString& filePath);

  // -------------------------------------------------------------------------
  // Writer thread
  // -------------------------------------------------------------------------
  class WriterThread : public QThread {
   public:
    explicit WriterThread(const QString& dbPath, ScanDatabase* owner);
    void enqueue(DatabaseWriteTask task);
    void requestStop();

   protected:
    void run() override;

   private:
    QString m_dbPath;
    ScanDatabase* m_owner;

    QMutex m_mutex;
    QWaitCondition m_cond;
    QQueue<DatabaseWriteTask> m_queue;
    bool m_stop = false;
  };

  // -------------------------------------------------------------------------
  // Data members
  // -------------------------------------------------------------------------
  QString m_dbPath;
  WriterThread* m_writerThread = nullptr;

  // Read-only connection opened on the UI thread for loadAll* calls.
  mutable sqlite3* m_readDb = nullptr;
};