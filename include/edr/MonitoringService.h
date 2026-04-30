#pragma once
// ============================================================================
// MonitoringService.h  –  Phase 4: lightweight EDR-Lite continuous monitor.
//
// Periodic-tick service that uses the existing SystemMonitor to capture
// snapshots, runs SnapshotDiff against the previous snapshot, and emits
// one Alert signal per detected change. UI components subscribe to
// alertRaised() and tickCompleted() to stay in sync.
//
// HARD LIMITS (per Phase 4 spec):
//   • No kernel hooks. No EndpointSecurity. No cloud. No quarantine.
//   • No file-tree scanning per tick — system snapshots only.
//   • Default disabled (cfg.edrLiteEnabled = false). User opts in.
//
// Threading:
//   • Lives on the UI thread.
//   • Heavy work happens inside SystemMonitor's worker thread (already
//     thread-safe). Diff runs on UI thread when snapshotReady arrives
//     via QueuedConnection — fast (set ops on small vectors).
//   • Overlap is prevented by checking SystemMonitor::isRefreshing()
//     before each tick. If true, we log and skip.
//
// Alert history:
//   • Stored in-memory as `m_alerts` (most-recent first), capped at
//     `kAlertHistoryCap`. Future work: persist to SQLite alongside scans.
// ============================================================================

#include "AlertTypes.h"
#include "../monitor/ProcessInfo.h"   // SystemSnapshot

#include <QObject>
#include <QDateTime>
#include <QVector>
#include <QHash>
#include <QAtomicInt>

class QTimer;
class SystemMonitor;

class MonitoringService : public QObject
{
    Q_OBJECT
public:
    explicit MonitoringService(SystemMonitor* sysmon, QObject* parent = nullptr);
    ~MonitoringService() override;

    /// Begin periodic ticking using the current ScannerConfig settings.
    /// Idempotent — calling start() while already running is a no-op.
    void start();

    /// Stop ticking. Idempotent.
    void stop();

    /// Re-read interval / toggles from ScannerConfigStore. Apply to the
    /// timer in-place. Safe to call any time. Useful right after the
    /// Settings page saves changes.
    void reloadConfig();

    bool      isRunning()       const;
    int       intervalSeconds() const;
    QDateTime lastTickAt()      const { return m_lastTick; }

    /// Most-recent-first alert history (capped at kAlertHistoryCap).
    /// Includes both Active and Resolved entries — the UI decides how to
    /// visually de-emphasize Resolved.
    QVector<EDR::Alert> alerts() const { return m_alerts; }
    int alertCount() const             { return m_alerts.size(); }

    /// Currently-active alerts indexed by dedupKey. Used by the
    /// risk-based Security Score engine — that needs the live picture,
    /// not historical noise.
    QHash<QString, EDR::Alert> activeAlerts() const { return m_active; }
    int activeAlertCount() const                    { return m_active.size(); }

signals:
    /// Fired ONCE per new finding (i.e. when a dedupKey appears that
    /// wasn't already active). Subsequent ticks observing the same
    /// condition silently bump lastSeen / ticksSeen.
    void alertRaised(const EDR::Alert& alert);

    /// Fired when an active alert's dedupKey is no longer present in
    /// the latest tick. The payload carries status=Resolved + resolvedAt.
    /// The same alert.id was previously surfaced via alertRaised, so UIs
    /// can match-and-update by id.
    void alertResolved(const EDR::Alert& alert);

    /// Fired when an active alert was already known and is still
    /// present — carries the bumped lastSeen / ticksSeen / occurrenceCount
    /// so UIs can refresh in place without rebuilding rows.
    void alertUpdated(const EDR::Alert& alert);

    /// Fired at the end of every successful tick. `alertsThisTick` is the
    /// number of NEW alerts (post-dedup) produced this round (0 means
    /// clean / only persistent conditions).
    void tickCompleted(int alertsThisTick, int durationMs);

    /// Fired when the service starts or stops (driven by start()/stop()
    /// or by config reload turning the master toggle on/off).
    void monitoringStateChanged(bool enabled);

private slots:
    void onTimerFired();
    void onSnapshotReady(const SystemSnapshot& snap);

private:
    static constexpr int kAlertHistoryCap = 500;

    SystemMonitor*       m_sysmon       = nullptr;
    QTimer*              m_timer        = nullptr;
    bool                 m_running      = false;
    bool                 m_haveBaseline = false;
    bool                 m_tickPending  = false;   // we kicked refresh, waiting for snapshotReady
    QDateTime            m_tickStartedAt;
    QDateTime            m_lastTick;
    SystemSnapshot       m_prev;

    // Append-only history (most-recent-first). Resolved entries are
    // updated in place when their condition disappears.
    QVector<EDR::Alert>  m_alerts;

    // Live dedup map: dedupKey → currently-active alert. An alert is in
    // here as long as it was observed in the most recent tick. Resolved
    // alerts are removed from this map (but kept in m_alerts for audit).
    QHash<QString, EDR::Alert> m_active;
};
