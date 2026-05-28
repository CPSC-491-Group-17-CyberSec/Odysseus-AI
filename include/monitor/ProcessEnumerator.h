#pragma once
// ============================================================================
// ProcessEnumerator.h  –  Phase 2: cross-platform process listing
//
// Single entry point: ProcessEnumerator::list(out, restrictedCount). Returns
// true on success. The implementation in ProcessEnumerator.cpp is selected
// at compile time:
//   • macOS  – sysctl(KERN_PROC_ALL) + libproc
//   • Linux  – /proc walking
//   • other  – stub returns empty list
//
// All output is read-only metadata; we never inspect process memory, signal
// processes, or otherwise interact with them beyond what the kernel offers
// to a regular unprivileged user.
// ============================================================================

#include "monitor/ProcessInfo.h"

namespace ProcessEnumerator {

/// Snapshot every visible process on this host.
///
/// out             – appended to (caller may reserve)
/// restrictedCount – out: how many processes had unreadable cmdline / path
///                   due to EPERM. Useful for the UI to show "12 processes
///                   had restricted metadata".
/// Returns true on success, false if the underlying syscall failed entirely.
///
/// Cost: ~2–10 ms on a typical desktop with 400–700 processes. Safe to call
/// from a worker thread; takes no global locks.
bool list(QVector<ProcessInfo>& out, int& restrictedCount);

/// Resolve a Unix uid to a username via getpwuid_r. Returns "uid:<n>" on
/// failure. Pure helper, no caching.
QString resolveUser(int uid);

}  // namespace ProcessEnumerator
