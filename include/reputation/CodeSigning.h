#pragma once
// ============================================================================
// CodeSigning.h  –  Phase 1: signature verification (macOS + Linux user-space)
//
// Why this matters:
//   A signed binary tells you who's accountable for the code. A binary in
//   /Applications that fails signature verification is a strong signal of
//   tampering or supply-chain compromise — far stronger than ML anomaly
//   scores alone. We cache the result per-hash in ReputationDB so we only
//   pay the codesign(1) / sigtool fork cost once per file.
//
// Cross-platform strategy:
//   • macOS:   shell out to `codesign -dv --verbose=2 <path>` and parse the
//              Authority / TeamIdentifier lines from stderr. Fast (~30 ms),
//              works on every macOS version since 10.5, no entitlements
//              required for signature inspection (unlike validation).
//   • Linux:   most desktop binaries are not signed. We check:
//                - dpkg -S <path>     → file owned by a package = trusted
//                - rpm -qf <path>     → same idea, RPM-based distros
//                - else:                Unsigned
//              Real ELF signature verification (e.g. linux kernel module
//              signatures) is out of scope for Phase 1.
//   • Windows: stubbed (returns Unknown) — not a target for Phase 1.
//
// All operations are user-space, no admin/root required.
// ============================================================================

#include <QString>

namespace CodeSigning {

enum class Status {
  Unknown = -1,         // we couldn't determine — treat as no signal
  Unsigned = 0,
  SignedUntrusted = 1,  // signed, but not by an Apple-trusted authority
  SignedTrusted = 2,    // signed by a recognized authority
};

struct Result {
  Status status = Status::Unknown;
  QString signerId;    // Apple Authority / TeamID / dpkg package name
  QString rawDetails;  // first ~512 chars of underlying tool output
};

/// Verify the signature of a single file. Synchronous; typical cost is
/// 30–80 ms on macOS for an unsigned file, 50–150 ms for a signed app
/// binary. Safe to call concurrently from worker threads.
Result verifyFile(const QString& filePath);

/// Convenience: convert a Status to a small int that ReputationDB stores
/// (matches ReputationRecord::signingStatus convention).
inline int statusToInt(Status s) {
  return static_cast<int>(s);
}
inline Status statusFromInt(int v) {
  if (v == 2)
    return Status::SignedTrusted;
  if (v == 1)
    return Status::SignedUntrusted;
  if (v == 0)
    return Status::Unsigned;
  return Status::Unknown;
}

QString statusToText(Status s);

}  // namespace CodeSigning
