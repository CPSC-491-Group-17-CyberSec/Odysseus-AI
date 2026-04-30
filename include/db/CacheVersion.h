#pragma once
// ============================================================================
// CacheVersion.h  –  Phase 5 follow-up: model/rules/config-aware cache keys.
//
// Why this exists:
//   The scan_cache table avoided re-scanning files whose (path, mtime, size)
//   were unchanged. But a clean verdict from before a model upgrade is no
//   longer trustworthy — the new model might flag the same bytes. Same
//   problem for YARA rule changes and ScannerConfig toggles.
//
// What we store:
//   • modelVersion  — concatenated SHA-256 of the AI model files in
//                     <appDir>/data/. Cheap to compute (mmap + hash).
//   • rulesVersion  — recursive max(mtime) of the yara_rules directory
//                     plus a count of .yar files. Cheap, stable, and
//                     fires whenever any rule is added/edited.
//   • configHash    — SHA-256 of ScannerConfig::toJson() compact form.
//
// On loadScanCache(), rows whose stored version triple does NOT match the
// current triple are skipped — those files get re-scanned. Rows from old
// installs (NULL columns) never match either, which is the correct safe
// behavior on upgrade.
//
// All three computations are cached in a static struct after first call;
// they don't change for the life of the process. Cheap to call repeatedly.
// ============================================================================

#include <QString>

namespace CacheVersion {

/// Concatenated SHA-256 of all detected model files (v2/v3 ONNX, v4 ONNX,
/// LightGBM model). Returns empty string if no model file is found, in
/// which case loadScanCache() will keep all rows that have an empty
/// model_version column (i.e. previously cached when no model was around).
QString modelVersion();

/// Recursive max(mtime) + file count for yara_rules/ tree. Format:
///   "<count>:<latest_mtime_iso>". Returns empty string if no rules dir
/// exists.
QString rulesVersion();

/// SHA-256 of the current ScannerConfig serialized as compact JSON.
/// Cheap; depends only on the in-memory config struct.
QString configHash();

/// Force-recompute (used by tests and by Settings → Reset).
void invalidate();

}  // namespace CacheVersion
