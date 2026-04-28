// ============================================================================
// RootkitMonitor.cpp  –  ties the three rootkit sub-checks together
// ============================================================================

#include "rootkit/RootkitMonitor.h"
#include "rootkit/ProcessCrossView.h"
#include "rootkit/KernelExtensionScanner.h"
#include "rootkit/IntegrityChecker.h"

#include "core/ScannerConfig.h"

#include <QElapsedTimer>
#include <QDebug>

namespace RootkitMonitor {

void scan(const QVector<ProcessInfo>& existingProcesses,
          RootkitSnapshot&            snap)
{
    const ScannerConfig& cfg = ScannerConfigStore::current();

    if (!cfg.rootkitAwarenessEnabled) {
        snap.ran = false;
        qInfo() << "[Rootkit] rootkitAwarenessEnabled=false — skipping all checks";
        return;
    }

    snap.ran = true;
    QElapsedTimer t; t.start();

    // ── Cross-view ──────────────────────────────────────────────────────
    if (cfg.processCrossViewCheckEnabled) {
        ProcessCrossView::diff(existingProcesses,
                                snap.crossView,
                                snap.processSysctlCount,
                                snap.processPsCount);
    } else {
        qInfo() << "[Rootkit] processCrossViewCheckEnabled=false — skipping";
    }

    // ── Kernel / system extensions ──────────────────────────────────────
    const qint64 afterCrossView = t.elapsed();
    if (cfg.kernelExtensionCheckEnabled) {
        KernelExtensionScanner::list(snap.extensions, snap.extensionsTotal);
        if (cfg.verboseLogging) {
            qDebug().noquote()
                << QString("[Rootkit] kernel extension scan took %1 ms")
                      .arg(t.elapsed() - afterCrossView);
        }
    } else {
        qInfo() << "[Rootkit] kernelExtensionCheckEnabled=false — skipping";
    }

    // ── Integrity check ─────────────────────────────────────────────────
    const qint64 afterKext = t.elapsed();
    if (cfg.integrityCheckEnabled) {
        IntegrityChecker::verify(snap.integrity,
                                  snap.integrityChecked,
                                  snap.integrityMismatches,
                                  snap.baselineCreated,
                                  snap.baselineRebased,
                                  snap.macosVersion);
        if (cfg.verboseLogging) {
            qDebug().noquote()
                << QString("[Rootkit] integrity verify took %1 ms")
                      .arg(t.elapsed() - afterKext);
        }
    } else {
        qInfo() << "[Rootkit] integrityCheckEnabled=false — skipping";
    }

    qInfo().noquote()
        << QString("[Rootkit] pass complete in %1 ms — "
                   "crossView=%2 extensions=%3 integrity=%4 (mismatches=%5)")
              .arg(t.elapsed())
              .arg(snap.crossView.size())
              .arg(snap.extensions.size())
              .arg(snap.integrity.size())
              .arg(snap.integrityMismatches);
}

}  // namespace RootkitMonitor
