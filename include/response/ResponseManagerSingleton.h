#pragma once
// =============================================================================
// Odysseus-AI  -  Phase 5 integration
// File: include/response/ResponseManagerSingleton.h
//
// Process-wide accessor for the response subsystem. Mirrors the existing
// pattern used by ReputationDB / AnomalyDetector singletons in the codebase
// (see odysseus_getReputationDB() in FileScannerYaraReputation.cpp).
//
// Why a singleton:
//   The detector path (FileScannerHash::runHashWorker) needs to consult the
//   Allowlist to suppress allowlisted findings, and the UI (ResultsPage)
//   needs to call ResponseManager::execute() when the user clicks Quarantine.
//   A back-pointer through MainWindow would force every subsystem to know
//   about every other; a process-wide accessor decouples them.
//
// Threading:
//   ResponseManager is thread-safe by construction (Allowlist / Quarantine /
//   ActionLog all hold internal mutexes). The first call lazy-initializes
//   the static instance under Meyer's-singleton rules; subsequent calls are
//   lock-free reads of a stable reference.
// =============================================================================

#include "response/ResponseManager.h"

namespace odysseus::response {

/// Returns the process-wide ResponseManager. Lazy-initialized on first call
/// using ResponseManager's default constructor (platform app-data paths,
/// POSIX process control, no-op UI bridge by default).
///
/// Safe to call from any thread.
ResponseManager& globalResponseManager();

/// Convenience accessor for the allowlist owned by the global manager.
/// Returns nullptr only if the global manager somehow hasn't been built —
/// in practice always non-null after the first call.
Allowlist* globalAllowlist();

}  // namespace odysseus::response
