// ============================================================================
// MonitoringService.cpp
// ============================================================================

#include "edr/MonitoringService.h"

#include <QDebug>
#include <QElapsedTimer>
#include <QMetaType>
#include <QTimer>

#include "core/ScannerConfig.h"
#include "edr/SnapshotDiff.h"
#include "monitor/SystemMonitor.h"

MonitoringService::MonitoringService(SystemMonitor* sysmon, QObject* parent)
    : QObject(parent),
      m_sysmon(sysmon) {
  qRegisterMetaType<EDR::Alert>("EDR::Alert");

  m_timer = new QTimer(this);
  m_timer->setTimerType(Qt::CoarseTimer);  // 1-second precision is fine
  connect(m_timer, &QTimer::timeout, this, &MonitoringService::onTimerFired);

  if (m_sysmon) {
    connect(
        m_sysmon,
        &SystemMonitor::snapshotReady,
        this,
        &MonitoringService::onSnapshotReady,
        Qt::QueuedConnection);
  }
}

MonitoringService::~MonitoringService() {
  stop();
}

// ============================================================================
//  Lifecycle
// ============================================================================
bool MonitoringService::isRunning() const {
  return m_running && m_timer && m_timer->isActive();
}

int MonitoringService::intervalSeconds() const {
  const ScannerConfig& cfg = ScannerConfigStore::current();
  // Clamp to a sane range — 5s minimum (anything tighter would burn
  // CPU on a polling system), 1h maximum (above that the user should
  // just disable EDR-Lite).
  return qBound(5, cfg.monitoringIntervalSeconds, 3600);
}

void MonitoringService::start() {
  if (m_running)
    return;
  if (!m_sysmon) {
    qWarning() << "[EDR] cannot start — no SystemMonitor available";
    return;
  }

  const int sec = intervalSeconds();
  m_timer->start(sec * 1000);
  m_running = true;
  m_haveBaseline = false;  // first tick captures baseline
  m_tickPending = false;
  qInfo().noquote() << QString("[EDR] monitoring enabled interval=%1s").arg(sec);
  emit monitoringStateChanged(true);

  // Kick an immediate first tick so the user sees activity right away
  // instead of waiting one full interval.
  QTimer::singleShot(0, this, &MonitoringService::onTimerFired);
}

void MonitoringService::stop() {
  if (!m_running)
    return;
  if (m_timer)
    m_timer->stop();
  m_running = false;
  m_tickPending = false;
  // Forget the active-set — when monitoring resumes we'll rebuild
  // baseline + active state from scratch instead of resurrecting stale
  // entries that may no longer apply.
  m_active.clear();
  m_haveBaseline = false;
  qInfo() << "[EDR] monitoring disabled";
  emit monitoringStateChanged(false);
}

void MonitoringService::reloadConfig() {
  const ScannerConfig& cfg = ScannerConfigStore::current();

  // Master toggle — turn the service on/off as the user flips it in
  // the Settings page. We don't re-emit alerts on toggle; existing
  // history is preserved.
  if (cfg.edrLiteEnabled && !m_running) {
    start();
  } else if (!cfg.edrLiteEnabled && m_running) {
    stop();
  }

  // Live-update the interval if it changed while we're already running.
  if (m_running && m_timer) {
    const int sec = intervalSeconds();
    if (m_timer->interval() != sec * 1000) {
      m_timer->setInterval(sec * 1000);
      qInfo().noquote() << QString("[EDR] interval updated to %1s").arg(sec);
    }
  }
}

// ============================================================================
//  Tick flow
// ============================================================================
void MonitoringService::onTimerFired() {
  if (!m_running)
    return;
  if (!m_sysmon)
    return;

  // Don't let ticks pile up. If our previous tick is still waiting on a
  // snapshot, OR the SystemMonitor has another caller in flight, skip.
  if (m_tickPending || m_sysmon->isRefreshing()) {
    qInfo() << "[EDR] previous monitoring tick still running — skipping";
    return;
  }

  qInfo() << "[EDR] tick started";
  m_tickStartedAt = QDateTime::currentDateTime();
  m_tickPending = true;
  m_sysmon->refresh();
}

void MonitoringService::onSnapshotReady(const SystemSnapshot& snap) {
  // Snapshots can arrive from refreshes WE didn't trigger (the user
  // clicking Refresh on the System Status page also fires this signal).
  // We still want to capture them for our diff baseline / next-tick
  // comparison, but we only count an "alert tick" when WE kicked it.
  const bool wasOurTick = m_tickPending;
  m_tickPending = false;

  QElapsedTimer dur;
  dur.start();

  SnapshotDiff::DiffResult dr;
  if (!m_haveBaseline) {
    // First snapshot — no comparison possible. We still seed m_active
    // by treating every condition in `snap` as a "first observation",
    // which avoids a noisy first-real-tick where everything appears
    // brand-new at once.
    m_haveBaseline = true;
    const ScannerConfig& cfg = ScannerConfigStore::current();
    // Diff against itself ⇒ no newAlerts, but currentKeys is populated.
    dr = SnapshotDiff::diff(snap, snap, cfg);
  } else {
    const ScannerConfig& cfg = ScannerConfigStore::current();
    dr = SnapshotDiff::diff(m_prev, snap, cfg);
  }

  // Promote curr → prev for next tick's comparison.
  m_prev = snap;
  m_lastTick = QDateTime::currentDateTime();

  int trulyNew = 0;
  int updated = 0;
  int resolved = 0;

  // ── 1. NEW: dedupKey not yet in m_active → emit alertRaised ────────
  //         (also covers conditions that briefly disappeared and came
  //          back: SnapshotDiff puts them in newAlerts because they
  //          weren't in `prev`, and m_active no longer holds them
  //          because they were resolved.)
  for (const EDR::Alert& a : dr.newAlerts) {
    if (a.dedupKey.isEmpty()) {
      // Defensive — alerts without a dedupKey can't dedup.
      // Treat as raise-once-and-forget.
      m_alerts.prepend(a);
      if (m_alerts.size() > kAlertHistoryCap)
        m_alerts.resize(kAlertHistoryCap);
      emit alertRaised(a);
      ++trulyNew;
      continue;
    }
    if (m_active.contains(a.dedupKey)) {
      // Already tracked (shouldn't happen — newAlerts are by
      // definition not in prev — but be defensive).
      EDR::Alert& existing = m_active[a.dedupKey];
      existing.lastSeen = QDateTime::currentDateTime();
      existing.ticksSeen++;
      existing.occurrenceCount++;
      // Update the corresponding history entry too.
      for (EDR::Alert& h : m_alerts) {
        if (h.id == existing.id) {
          h.lastSeen = existing.lastSeen;
          h.ticksSeen = existing.ticksSeen;
          h.occurrenceCount = existing.occurrenceCount;
          break;
        }
      }
      emit alertUpdated(existing);
      ++updated;
      continue;
    }

    EDR::Alert fresh = a;
    fresh.status = EDR::AlertStatus::Active;
    fresh.ticksSeen = 1;
    m_active.insert(fresh.dedupKey, fresh);
    m_alerts.prepend(fresh);
    if (m_alerts.size() > kAlertHistoryCap)
      m_alerts.resize(kAlertHistoryCap);
    qInfo().noquote() << QString("[EDR] alert %1 %2: %3 (key=%4)")
                             .arg(
                                 EDR::severityToText(fresh.severity).toUpper(),
                                 fresh.category,
                                 fresh.title,
                                 fresh.dedupKey);
    emit alertRaised(fresh);
    ++trulyNew;
  }

  // ── 2. PERSIST: keys in currentKeys that we already track →
  //               bump lastSeen + ticksSeen, no emit (silent persistence)
  //               but emit alertUpdated so UIs can refresh in place.
  for (auto it = dr.currentKeys.constBegin(); it != dr.currentKeys.constEnd(); ++it) {
    if (!m_active.contains(it.key()))
      continue;
    // Skip ones we just inserted as new this tick.
    // (newAlerts are also in currentKeys; the bump would double-count
    //  ticksSeen.)
    bool wasJustInserted = false;
    for (const EDR::Alert& a : dr.newAlerts) {
      if (a.dedupKey == it.key()) {
        wasJustInserted = true;
        break;
      }
    }
    if (wasJustInserted)
      continue;

    EDR::Alert& existing = m_active[it.key()];
    existing.lastSeen = QDateTime::currentDateTime();
    existing.ticksSeen++;
    existing.occurrenceCount++;
    // Refresh the history entry in place so the UI's detail panel
    // sees the new lastSeen/occurrenceCount on next read.
    for (EDR::Alert& h : m_alerts) {
      if (h.id == existing.id) {
        h.lastSeen = existing.lastSeen;
        h.ticksSeen = existing.ticksSeen;
        h.occurrenceCount = existing.occurrenceCount;
        break;
      }
    }
    emit alertUpdated(existing);
    ++updated;
  }

  // ── 3. RESOLVE: anything in m_active NOT present in currentKeys →
  //               flip to Resolved and emit alertResolved.
  QStringList resolvedKeys;
  for (auto it = m_active.constBegin(); it != m_active.constEnd(); ++it) {
    if (!dr.currentKeys.contains(it.key()))
      resolvedKeys.append(it.key());
  }
  for (const QString& k : resolvedKeys) {
    EDR::Alert resolvedAlert = m_active.take(k);
    resolvedAlert.status = EDR::AlertStatus::Resolved;
    resolvedAlert.resolvedAt = QDateTime::currentDateTime();

    // Update the history entry in place.
    for (EDR::Alert& h : m_alerts) {
      if (h.id == resolvedAlert.id) {
        h.status = EDR::AlertStatus::Resolved;
        h.resolvedAt = resolvedAlert.resolvedAt;
        break;
      }
    }
    qInfo().noquote() << QString("[EDR] resolved %1 %2: %3 (key=%4, ticks=%5)")
                             .arg(
                                 EDR::severityToText(resolvedAlert.severity).toUpper(),
                                 resolvedAlert.category,
                                 resolvedAlert.title,
                                 resolvedAlert.dedupKey)
                             .arg(resolvedAlert.ticksSeen);
    emit alertResolved(resolvedAlert);
    ++resolved;
  }

  if (wasOurTick) {
    const int ms = static_cast<int>(dur.elapsed());
    qInfo().noquote() << QString(
                             "[EDR] tick complete new=%1 persist=%2 resolved=%3 "
                             "active=%4 duration=%5ms")
                             .arg(trulyNew)
                             .arg(updated)
                             .arg(resolved)
                             .arg(m_active.size())
                             .arg(ms);
    emit tickCompleted(trulyNew, ms);
  }
}
