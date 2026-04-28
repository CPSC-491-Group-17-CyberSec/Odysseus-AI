#pragma once
// ============================================================================
// RootkitMonitor.h  –  Phase 3: rootkit-awareness orchestrator
//
// Plain namespace-style API (not a QObject) — the SystemMonitor worker
// thread calls scan() inline as part of its single-shot snapshot pass.
// All thread safety comes from the existing single-worker contract on
// SystemMonitor.
//
// Reads from ScannerConfigStore for the four toggles:
//   • rootkitAwarenessEnabled       – master switch (off → ran=false)
//   • processCrossViewCheckEnabled  – sysctl ↔ ps diff
//   • kernelExtensionCheckEnabled   – systemextensionsctl + kmutil
//   • integrityCheckEnabled         – baseline + verify
// ============================================================================

#include "rootkit/RootkitTypes.h"
#include "monitor/ProcessInfo.h"

namespace RootkitMonitor {

/// Run the full rootkit-awareness pass. Populates the supplied snapshot
/// in-place. Designed to be called from SystemMonitor::run() between the
/// existing process/persistence steps.
///
/// existingProcesses – the sysctl process list captured earlier in the same
///                      refresh tick (passed in to avoid re-hashing)
void scan(const QVector<ProcessInfo>& existingProcesses,
          RootkitSnapshot&            snap);

}  // namespace RootkitMonitor
