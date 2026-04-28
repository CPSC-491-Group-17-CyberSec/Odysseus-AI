#pragma once
// ============================================================================
// SuspiciousHeuristics.h  –  Phase 2: process-flagging logic
//
// Cross-platform: nothing here calls a syscall. We operate purely on the
// metadata already collected in ProcessInfo. Each heuristic contributes a
// reason string and a numeric weight; the sum produces a 0–100 score. Score
// thresholds map to severity:
//   ≥ 60 high   |   30–59 medium   |   1–29 low   |   0 not flagged
//
// Heuristic catalog (all read-only, all fast):
//
//   PathFromTmp                — exe in /tmp, /var/tmp, /private/{tmp,var/tmp}
//   PathFromDownloads         — exe in any user's Downloads directory
//   PathHidden                 — any segment of the exe path starts with '.'
//   ExeMissing                 — exe was unlinked while process kept running
//   RandomLookingName          — process name has high digit/random ratio
//   SuspiciousCmdLine          — flags / patterns associated with droppers,
//                                 reverse shells, encoded payloads
//   UnsignedExecutable         — codesign / signature check failed (macOS+Linux)
//   RootFromUserPath           — running as root from a user-writable path
// ============================================================================

#include "monitor/ProcessInfo.h"

namespace SuspiciousHeuristics {

/// Evaluate every process and return only the suspicious ones, sorted by
/// score descending.
///
/// processes        – input list (typically from ProcessEnumerator::list())
/// checkSigning    – when true, runs CodeSigning::verifyFile() per flagged
///                    process (slow: 30–80 ms each on macOS). Set false on
///                    fast refresh; enable for the on-demand "deep check".
QVector<SuspiciousProcess> evaluate(const QVector<ProcessInfo>& processes,
                                     bool checkSigning);

/// Test-only helpers exposed for the suspicious-process detail panel —
/// these run a single rule and return the reason string if it would have
/// flagged the process.
QString testPath(const ProcessInfo& p);
QString testExeMissing(const ProcessInfo& p);
QString testRandomName(const ProcessInfo& p);
QString testCmdLine(const ProcessInfo& p);
QString testRootFromUserPath(const ProcessInfo& p);

}  // namespace SuspiciousHeuristics
