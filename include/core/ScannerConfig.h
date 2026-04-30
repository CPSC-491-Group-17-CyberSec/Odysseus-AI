#pragma once
// ============================================================================
// ScannerConfig.h  –  Phase 1.5: per-feature toggles for the scanner pipeline
//
// The config is intentionally simple and human-editable:
//   • Single JSON file at <AppData>/odysseus_config.json
//   • Defaults are baked into the struct, so a missing/broken file just falls
//     back to "everything on, verbose off, experimental off".
//   • Lazy-loaded singleton matching the AnomalyDetector / ReputationDB
//     pattern in this codebase. Thread-safe reads after first load.
//
// Why these specific toggles:
//   yaraEnabled            – disable when libyara is causing false positives
//                            during rule tuning, or for triage runs where
//                            speed matters more than coverage.
//   reputationAutoUpsert   – disable in "read-only" forensic-style scans so
//                            the reputation table doesn't grow with samples
//                            from this host. Lookups still work.
//   codeSigningEnabled     – disable on Linux servers where every binary is
//                            unsigned and the codesign output is noise; or
//                            in benchmarks (codesign forks a process).
//   verboseLogging         – flip on when debugging detection issues. Gates
//                            the per-file PIPELINE diagnostic dump and other
//                            chatty traces that are silent by default.
//   experimentalRules      – ship aggressive/noisy rules in
//                            data/yara_rules/experimental/ that we WANT
//                            to test but don't want firing on every user.
//
// All fields have safe-default backwards compatibility: adding a new bool
// later just adds a new fromJson() case; old config files keep working.
// ============================================================================

#include <QJsonObject>
#include <QString>

// ---------------------------------------------------------------------------
// ScannerConfig  –  plain value type (copyable, comparable)
// ---------------------------------------------------------------------------
struct ScannerConfig {
  // ── Feature toggles ────────────────────────────────────────────────
  bool yaraEnabled = true;
  bool reputationAutoUpsert = true;
  bool codeSigningEnabled = true;
  bool verboseLogging = false;
  bool experimentalRules = false;

  // ── Phase 2: System Monitoring toggles ─────────────────────────────
  // Master switch first; the three sub-toggles are no-ops if the master
  // is off. This lets the user kill all system probing with one flag.
  bool systemMonitoringEnabled = true;
  bool processScanEnabled = true;
  bool persistenceScanEnabled = true;
  bool suspiciousProcessHeuristicsEnabled = true;

  // ── Phase 3: Rootkit Awareness toggles ─────────────────────────────
  // All three sub-checks are user-space only. Master switch off → none
  // of them run, regardless of the sub-toggle states.
  bool rootkitAwarenessEnabled = true;
  bool processCrossViewCheckEnabled = true;
  bool kernelExtensionCheckEnabled = true;
  bool integrityCheckEnabled = true;

  // ── Phase 4: EDR-Lite continuous monitoring (BETA) ─────────────────
  // Default disabled — user opts in via Settings. When enabled, the
  // MonitoringService runs SystemMonitor::refresh() every
  // monitoringIntervalSeconds and emits Alerts on diffs.
  bool edrLiteEnabled = false;
  int monitoringIntervalSeconds = 15;
  bool alertOnNewProcess = true;
  bool alertOnNewPersistence = true;
  bool alertOnIntegrityMismatch = true;
  bool alertOnKernelExtensionChange = true;

  // ── Tunables ───────────────────────────────────────────────────────
  /// Subdirectory (relative to YARA rules dir) holding aggressive/noisy
  /// rules that are skipped unless experimentalRules is true.
  QString experimentalSubdir = "experimental";

  /// Hard cap on YARA compile errors before we give up on a rules dir.
  /// Prevents one corrupt .yar from spamming the log indefinitely.
  int maxCompileErrors = 100;

  // ── Serialization ──────────────────────────────────────────────────
  QJsonObject toJson() const;
  static ScannerConfig fromJson(const QJsonObject& obj);
};

// ---------------------------------------------------------------------------
// ScannerConfigStore  –  process-wide accessor
// ---------------------------------------------------------------------------
namespace ScannerConfigStore {

/// Snapshot of the current config. Cheap; safe to call from worker threads.
const ScannerConfig& current();

/// Replace the config and persist to disk. Returns false if the file write
/// fails (the in-memory copy is still updated either way).
bool set(const ScannerConfig& c);

/// Force a fresh read from disk. Useful if the user edits the file by hand
/// while the app is running.
void reload();

/// Absolute path to the config file (for the UI to surface in About / Settings).
QString configPath();

/// Reset to factory defaults and persist. Returns the new config.
ScannerConfig resetToDefaults();

}  // namespace ScannerConfigStore
