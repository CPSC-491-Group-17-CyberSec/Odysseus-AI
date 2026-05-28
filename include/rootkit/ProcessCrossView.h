#pragma once
// ============================================================================
// ProcessCrossView.h  –  Phase 3: sysctl ↔ ps PID-set diff
//
// Why this matters:
//   A user-space rootkit hiding a process typically has to lie to BOTH
//   the kernel-side process listing AND the userland tools that read it.
//   Lazy / partial hooks frequently lie to one but not the other. By
//   capturing both views nearly simultaneously and diffing, we surface
//   exactly those inconsistencies.
//
// What we don't catch:
//   A clean kernel rootkit hooks every interface consistently. This check
//   is a cheap user-space heuristic, not a kernel forensic tool.
//
// macOS notes:
//   • Source A: ProcessEnumerator (already uses sysctl(KERN_PROC_ALL))
//   • Source B: /bin/ps -axo pid=,comm=
//   • Both are read inside ~10 ms of each other to minimize transient
//     process churn from polluting the diff.
//
// Linux notes (scaffolded but not wired up to a separate "ps" view yet):
//   /proc walking IS the only authoritative source on Linux. We'd need
//   `ps` from procps as the second source, but the diff would just be
//   the same source twice. So on Linux this returns an empty result with
//   a "not applicable on this platform" note.
// ============================================================================

#include "monitor/ProcessInfo.h"
#include "rootkit/RootkitTypes.h"

namespace ProcessCrossView {

/// Compare a pre-collected sysctl process list against a fresh `ps` output.
///
/// existing — the list returned by ProcessEnumerator::list() in the same
///            refresh tick. Reusing it avoids hashing the kernel twice.
/// out      — appended findings (PIDs that disagreed)
/// Returns true if the comparison ran successfully; false if `ps` was
/// unreachable or returned nothing parseable.
bool diff(
    const QVector<ProcessInfo>& existing,
    QVector<CrossViewFinding>& out,
    int& sysctlCountOut,
    int& psCountOut);

}  // namespace ProcessCrossView
