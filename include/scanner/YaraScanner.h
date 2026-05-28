#pragma once
// ============================================================================
// YaraScanner.h  –  Phase 1: third detection pass (after hash, before AI)
//
// Why YARA matters in the pipeline:
//   • Hash matching is exact-only — one byte changed and the lookup misses.
//   • ML scoring is probabilistic and prone to drift on novel benign software.
//   • YARA rules are deterministic pattern matchers, written by analysts to
//     describe a malware family's invariants (strings, byte sequences,
//     PE-section names, etc.). They catch repacked / lightly-modified samples
//     that flat hash blocklists miss, with explanations the user can audit.
//
// Design:
//   • Wraps libyara's C API behind an RAII C++ class — no manual yr_finalize.
//   • Singleton-friendly: rules are compiled once at first use and shared
//     (libyara's YR_RULES is thread-safe for scanning, not for compilation).
//   • Builds even when libyara is absent (ODY_HAS_YARA undefined): then the
//     ::initialize() call is a no-op and ::scanFile() always returns no match.
//   • Match results are returned as a small struct, not raw libyara pointers,
//     so callers never need to include <yara.h>.
//
// Thread safety:
//   • initialize() must be called once before any scan; subsequent calls are
//     no-ops. Wrap with QMutex if multiple threads might race the first call.
//   • scanFile() is safe to call concurrently from N threads after init.
// ============================================================================

#include <QHash>
#include <QString>
#include <QStringList>
#include <QVector>

// ---------------------------------------------------------------------------
// YaraMatch  –  one rule that fired on a file
// ---------------------------------------------------------------------------
struct YaraMatch {
  QString ruleName;       // "Generic_Suspicious_PE", "EICAR_Test_File", ...
  QString ruleNamespace;  // optional grouping ("malware", "packer", ...)
  QString family;         // metadata: family= "Emotet", "WannaCry", ...
  QString description;    // metadata: description= "..."
  QString severity;       // metadata: severity= "low/medium/high/critical"
  QStringList tags;       // YARA rule tags (banker, ransomware, ...)
};

// ---------------------------------------------------------------------------
// YaraScanResult  –  full result of one file scan
// ---------------------------------------------------------------------------
struct YaraScanResult {
  bool hadError = false;       // true if libyara returned an error
  QString errorString;         // populated when hadError
  QVector<YaraMatch> matches;  // empty when no rules fired

  bool fired() const { return !matches.isEmpty(); }
};

// ---------------------------------------------------------------------------
// YaraInitOptions  –  parameters for YaraScanner::initialize()
// ---------------------------------------------------------------------------
struct YaraInitOptions {
  QString rulesDir;                  // absolute path to data/yara_rules
  bool includeExperimental = false;  // compile rules under <rulesDir>/experimental/
  QString experimentalSubdir = "experimental";
  int maxCompileErrors = 100;        // stop loading after this many errors
  bool verbose = false;              // log per-file compile detail
};

// ---------------------------------------------------------------------------
// YaraScanner  –  singleton-style API
// ---------------------------------------------------------------------------
namespace YaraScanner {

/// Initialize libyara and compile every .yar/.yara file under
/// opts.rulesDir (recursively). Safe to call multiple times — only the
/// first call does work. Returns true if at least one rule compiled
/// successfully.
///
/// Missing directory or libyara absence is non-fatal: the function returns
/// false and isAvailable() is false thereafter, with an explanatory log
/// line so the user knows why YARA is silent.
bool initialize(const YaraInitOptions& opts);

/// Backwards-compatible overload: defaults to no experimental rules,
/// 100-error cap, non-verbose.
bool initialize(const QString& rulesDir);

/// True if libyara was found at build time AND initialize() compiled at least
/// one rule. Use this to gate whether to run scanFile() at all.
bool isAvailable();

/// Number of compiled rules currently loaded (0 if not initialized).
int ruleCount();

/// Scan a single file against all loaded rules.
///
/// Cheap operations:
///   • <1 ms for files <100 KB and ~50 rules.
///   • Bound by sequential file read; uses memory-mapped I/O via libyara.
///
/// Safe to call concurrently from multiple threads after initialize() returns.
YaraScanResult scanFile(const QString& filePath);

/// Free all libyara state. Optional — destructor runs at process exit anyway.
void shutdown();

}  // namespace YaraScanner
