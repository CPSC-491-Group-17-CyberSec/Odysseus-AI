#pragma once
// ============================================================================
// SystemMonitor.h  –  Phase 2: orchestrator for system monitoring
//
// Single QObject the UI talks to. Encapsulates a one-shot worker thread that
// runs the three sub-passes (process enum, persistence scan, heuristics)
// off the UI thread, then emits a snapshot signal.
//
// Lifecycle:
//   • UI calls refresh()  → worker thread spawned
//   • Worker runs the three passes, emits snapshotReady(SystemSnapshot)
//   • Worker thread quits and is deleted
//   • UI may call refresh() again at any time; one snapshot at a time only
//     (subsequent calls during an in-flight refresh are ignored)
//
// Why no daemon:
//   The user explicitly scoped Phase 2 to "no background daemon yet". When
//   that changes, this same QObject can grow a QTimer + auto-refresh
//   without breaking its public API.
// ============================================================================

#include <QAtomicInt>
#include <QObject>
#include <QThread>

#include "monitor/ProcessInfo.h"

class SystemMonitorWorker;

class SystemMonitor : public QObject {
  Q_OBJECT
 public:
  explicit SystemMonitor(QObject* parent = nullptr);
  ~SystemMonitor() override;

  /// Kick off a system snapshot on a worker thread. Safe to call from the
  /// UI thread. Idempotent: a second call while a refresh is in-flight is
  /// ignored (returns false).
  bool refresh();

  /// True between refresh() and snapshotReady / snapshotError.
  bool isRefreshing() const;

  /// The most recent successful snapshot. Useful when the UI is shown
  /// before the user has clicked Refresh and we want to render whatever
  /// we last had (or empty defaults).
  const SystemSnapshot& lastSnapshot() const { return m_lastSnapshot; }

 signals:
  /// Emitted on the UI thread when a refresh completes.
  void snapshotReady(const SystemSnapshot& snapshot);

  /// Emitted on the UI thread on a hard failure.
  void snapshotError(const QString& message);

 private slots:
  void onWorkerFinished();

 private:
  QThread* m_thread = nullptr;
  SystemMonitorWorker* m_worker = nullptr;
  SystemSnapshot m_lastSnapshot;
  QAtomicInt m_busy{0};
};
