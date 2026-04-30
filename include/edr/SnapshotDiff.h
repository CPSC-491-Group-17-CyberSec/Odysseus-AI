#pragma once
// ============================================================================
// SnapshotDiff.h  –  Phase 4: pure stateless diff engine.
//
// Inputs : two SystemSnapshot values + the active ScannerConfig (so per-
//          category toggles can be honored).
// Output : a list of Alert values describing what's NEW or CHANGED in
//          curr that wasn't already in prev.
//
// "New" semantics:
//   • Suspicious process → (pid, exePath) tuple appears in curr but not prev
//   • Persistence item   → (type, label, filePath) tuple appears in curr
//                           but not prev
//   • Cross-view finding → pid appears in curr but not prev
//   • Integrity mismatch → path with status "mismatch" appears in curr
//                           but wasn't a mismatch in prev
//   • Kernel extension   → (bundleId, version) appears in curr but not prev,
//                           AND severity is medium/high (Apple-signed kexts
//                           are skipped to reduce noise)
//
// Pure function: no side effects, no I/O, no Qt event loop interaction.
// Safe to call from the UI thread; small / fast (set-ops on QVectors).
// ============================================================================

#include "AlertTypes.h"
#include "../monitor/ProcessInfo.h"   // SystemSnapshot
#include "../core/ScannerConfig.h"

#include <QVector>
#include <QSet>
#include <QHash>

namespace SnapshotDiff {

/// Result of one diff pass.
///
///   newAlerts   – alerts whose dedupKey was NOT present in prev (i.e.
///                 conditions that just appeared this tick)
///   currentKeys – every dedupKey present in curr, with the matching
///                 alert payload as value. MonitoringService uses this
///                 to (a) bump lastSeen / ticksSeen on persistent
///                 conditions and (b) detect resolution (active keys
///                 that are NOT in this set).
struct DiffResult {
    QVector<EDR::Alert>          newAlerts;
    QHash<QString, EDR::Alert>   currentKeys;
};

/// Compute alerts for everything new in `curr` vs `prev`, plus the full
/// keyed set of conditions present in `curr`. Honors the per-category
/// toggles in `cfg`. Pure function: no I/O, no event loop interaction.
DiffResult diff(const SystemSnapshot& prev,
                const SystemSnapshot& curr,
                const ScannerConfig&  cfg);

}  // namespace SnapshotDiff
