#pragma once
// ============================================================================
// IntegrityChecker.h  –  Phase 3: SHA-256 baseline of critical system paths
//
// Contract:
//   • First run: hash every critical path that exists on disk, store the
//     baseline as JSON under <AppData>/odysseus_integrity_baseline.json.
//     No findings emitted (other than informational "captured baseline").
//   • Subsequent runs: hash again, compare against baseline.
//       - hash matches  → "ok"      finding (low — informational)
//       - hash differs  → "mismatch" finding (high — INTEGRITY VIOLATION)
//       - file missing  → "missing"  finding (medium)
//       - new path      → "new"      finding (low — added to baseline)
//   • When the macOS major.minor version changes between runs, we treat
//     hash changes as expected (OS update) and silently rebase the
//     baseline. The user gets ONE info-level finding noting the rebase.
//
// Why this is high-signal on macOS:
//   The Sealed System Volume (SSV) makes the curated paths immutable
//   between OS updates. A hash difference under the same OS version
//   indicates either filesystem corruption or active tampering. Either
//   way the user wants to know.
// ============================================================================

#include "rootkit/RootkitTypes.h"

#include <QString>

namespace IntegrityChecker {

/// Run the full integrity verification: load baseline, hash each path,
/// compare, emit findings, save updated baseline.
///
/// out                 – appended findings (one per checked path, plus 0–1
///                        informational "rebase" or "baseline-created" entries)
/// checkedOut          – count of paths actually hashed
/// mismatchOut         – count of "mismatch" findings (the high-severity ones)
/// baselineCreatedOut  – out: true if this was the first run / baseline file
///                        was just created
/// baselineRebasedOut  – out: true if the baseline was silently rebased due
///                        to an OS-version change
bool verify(QVector<IntegrityFinding>& out,
            int& checkedOut,
            int& mismatchOut,
            bool& baselineCreatedOut,
            bool& baselineRebasedOut,
            QString& macosVersionOut);

/// Force-rebase: discard the existing baseline and hash everything fresh.
/// Useful as a manual "I just installed an update, trust the new hashes"
/// button. Returns the number of paths in the new baseline.
int forceRebase();

/// Path of the baseline JSON file (for diagnostics / About panel).
QString baselinePath();

}  // namespace IntegrityChecker
