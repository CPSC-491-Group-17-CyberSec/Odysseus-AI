// ============================================================================
// SystemMonitor.cpp
//
// Thread model mirrors FileScanner: a one-shot QThread + QObject worker.
// Each refresh() spawns a fresh worker; when the snapshot is ready the
// worker emits, the thread quits, and Qt's deleteLater cleans up.
// ============================================================================

#include "monitor/SystemMonitor.h"
#include "monitor/ProcessEnumerator.h"
#include "monitor/PersistenceScanner.h"
#include "monitor/SuspiciousHeuristics.h"
#include "rootkit/RootkitMonitor.h"
#include "core/ScannerConfig.h"

#include <QDebug>
#include <QElapsedTimer>
#include <QMetaType>

// ============================================================================
// Worker (lives on its own QThread)
// ============================================================================
class SystemMonitorWorker : public QObject
{
    Q_OBJECT
public:
    SystemMonitorWorker() = default;

public slots:
    void run()
    {
        const ScannerConfig& cfg = ScannerConfigStore::current();

        if (!cfg.systemMonitoringEnabled) {
            qInfo() << "[SysMon] systemMonitoringEnabled=false — skipping refresh";
            SystemSnapshot empty;
            empty.capturedAt    = QDateTime::currentDateTime();
            empty.platformLabel = "(disabled)";
            emit snapshotReady(empty);
            return;
        }

        SystemSnapshot snap;
        snap.capturedAt = QDateTime::currentDateTime();

#if defined(Q_OS_MACOS)
        snap.platformLabel = "macOS";
#elif defined(Q_OS_LINUX)
        snap.platformLabel = "Linux";
#else
        snap.platformLabel = "unknown";
#endif

        QElapsedTimer t; t.start();

        // ── Process enumeration ─────────────────────────────────────────
        if (cfg.processScanEnabled) {
            int restricted = 0;
            if (!ProcessEnumerator::list(snap.processes, restricted)) {
                qWarning() << "[SysMon] process enumeration failed";
            }
            snap.totalProcesses     = snap.processes.size();
            snap.restrictedCmdlines = restricted;
            qInfo().noquote()
                << QString("[SysMon] enumerated %1 process(es) in %2 ms "
                           "(%3 with restricted metadata)")
                       .arg(snap.totalProcesses)
                       .arg(t.elapsed())
                       .arg(restricted);
        } else {
            qInfo() << "[SysMon] processScanEnabled=false — skipping enumeration";
        }

        // ── Heuristics ─────────────────────────────────────────────────
        const qint64 enumMs = t.elapsed();
        if (cfg.suspiciousProcessHeuristicsEnabled && !snap.processes.isEmpty()) {
            // checkSigning=true is acceptable here because we only ran on
            // the suspect subset (typically <30 processes). A faster mode
            // can be exposed later via a config flag if needed.
            snap.suspicious = SuspiciousHeuristics::evaluate(snap.processes,
                                                              cfg.codeSigningEnabled);
            qInfo().noquote()
                << QString("[SysMon] heuristics flagged %1 process(es) in %2 ms")
                       .arg(snap.suspicious.size())
                       .arg(t.elapsed() - enumMs);
        } else if (!cfg.suspiciousProcessHeuristicsEnabled) {
            qInfo() << "[SysMon] suspiciousProcessHeuristicsEnabled=false — skipping heuristics";
        }

        // ── Persistence ─────────────────────────────────────────────────
        const qint64 heurMs = t.elapsed();
        if (cfg.persistenceScanEnabled) {
            int errs = 0;
            PersistenceScanner::scan(snap.persistence, errs);
            qInfo().noquote()
                << QString("[SysMon] persistence scan found %1 item(s) in %2 ms")
                       .arg(snap.persistence.size())
                       .arg(t.elapsed() - heurMs);
        } else {
            qInfo() << "[SysMon] persistenceScanEnabled=false — skipping persistence";
        }

        // ── Phase 3: Rootkit awareness ─────────────────────────────────
        const qint64 persistMs = t.elapsed();
        RootkitMonitor::scan(snap.processes, snap.rootkit);
        if (snap.rootkit.ran && cfg.verboseLogging) {
            qDebug().noquote()
                << QString("[SysMon] rootkit pass took %1 ms")
                       .arg(t.elapsed() - persistMs);
        }

        qInfo().noquote()
            << QString("[SysMon] snapshot complete in %1 ms — "
                       "platform=%2 processes=%3 suspicious=%4 persistence=%5 "
                       "rootkit=%6 (xview=%7 ext=%8 integ=%9)")
                .arg(t.elapsed())
                .arg(snap.platformLabel)
                .arg(snap.totalProcesses)
                .arg(snap.suspicious.size())
                .arg(snap.persistence.size())
                .arg(snap.rootkit.ran ? "ran" : "off")
                .arg(snap.rootkit.crossView.size())
                .arg(snap.rootkit.extensions.size())
                .arg(snap.rootkit.integrityMismatches);

        emit snapshotReady(snap);
    }

signals:
    void snapshotReady(const SystemSnapshot& snap);
};

// ============================================================================
// SystemMonitor (UI thread)
// ============================================================================
SystemMonitor::SystemMonitor(QObject* parent)
    : QObject(parent)
{
    // Register the metatypes we emit across thread boundaries.
    qRegisterMetaType<ProcessInfo>("ProcessInfo");
    qRegisterMetaType<SuspiciousProcess>("SuspiciousProcess");
    qRegisterMetaType<PersistenceItem>("PersistenceItem");
    qRegisterMetaType<SystemSnapshot>("SystemSnapshot");
    // Phase 3
    qRegisterMetaType<CrossViewFinding>("CrossViewFinding");
    qRegisterMetaType<KernelExtension>("KernelExtension");
    qRegisterMetaType<IntegrityFinding>("IntegrityFinding");
    qRegisterMetaType<RootkitSnapshot>("RootkitSnapshot");
}

SystemMonitor::~SystemMonitor()
{
    if (m_thread && m_thread->isRunning()) {
        m_thread->quit();
        m_thread->wait(2000);
    }
}

bool SystemMonitor::isRefreshing() const
{
    return m_busy.loadRelaxed() != 0;
}

bool SystemMonitor::refresh()
{
    if (!m_busy.testAndSetAcquire(0, 1)) {
        qInfo() << "[SysMon] refresh already in flight — ignoring";
        return false;
    }

    m_thread = new QThread(this);
    m_worker = new SystemMonitorWorker();
    m_worker->moveToThread(m_thread);

    connect(m_thread, &QThread::started,  m_worker, &SystemMonitorWorker::run);
    connect(m_worker, &SystemMonitorWorker::snapshotReady,
            this, [this](const SystemSnapshot& s) {
                m_lastSnapshot = s;
                emit snapshotReady(s);
            }, Qt::QueuedConnection);
    connect(m_worker, &SystemMonitorWorker::snapshotReady,
            m_thread, &QThread::quit);
    connect(m_thread, &QThread::finished, this, &SystemMonitor::onWorkerFinished);
    connect(m_thread, &QThread::finished, m_worker, &QObject::deleteLater);
    connect(m_thread, &QThread::finished, m_thread, &QObject::deleteLater);

    m_thread->start();
    return true;
}

void SystemMonitor::onWorkerFinished()
{
    m_thread = nullptr;
    m_worker = nullptr;
    m_busy.storeRelease(0);
}

#include "SystemMonitor.moc"   // for the local SystemMonitorWorker QObject
