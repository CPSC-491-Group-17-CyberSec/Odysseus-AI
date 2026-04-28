#pragma once
// ============================================================================
// PersistenceScanner.h  –  Phase 2: enumerate persistence mechanisms
//
// Persistence is how malware stays alive across reboots — and on macOS,
// LaunchAgents and LaunchDaemons are the dominant mechanism for both
// legitimate and malicious code. Scanning these directories regularly is
// one of the highest-signal user-space checks a security tool can do.
//
// Read-only: we never modify, sign, or unload anything we find. We just
// list it, parse the plist for the executable target, and surface notes
// (path looks suspicious, target file missing, target is unsigned, etc.).
//
// macOS persistence locations covered:
//   • ~/Library/LaunchAgents/*.plist            – per-user, user-loaded
//   • /Library/LaunchAgents/*.plist             – all users, user-loaded
//   • /Library/LaunchDaemons/*.plist            – system-wide, root-loaded
//   • crontab -l (current user)
//   • /etc/crontab, /etc/cron.{d,daily,hourly,weekly,monthly}
//   • /etc/periodic/*  (BSD-style legacy)
//
// Linux scaffolding (best-effort, safe defaults):
//   • /etc/crontab, /etc/cron.{d,daily,hourly,weekly,monthly}
//   • crontab -l (current user)
//   • /etc/systemd/system/*.service     (system unit files)
//   • ~/.config/systemd/user/*.service  (per-user unit files)
//
// We deliberately skip:
//   • /System/Library/LaunchDaemons    (Apple-managed, signed by Apple, noise)
//   • LoginItems plumbing (TCC-restricted, requires user prompt)
//   • Browser extensions, kernel extensions (out of Phase 2 scope)
// ============================================================================

#include "monitor/ProcessInfo.h"

namespace PersistenceScanner {

/// Snapshot every persistence item we can read.
///
/// out               – appended to (caller may reserve)
/// errorsLogged      – out: how many parse errors we suppressed (for the
///                     UI to show "we skipped 3 plists we couldn't parse")
/// Returns true if at least one location was readable. Returns false only
/// if every location failed (extremely rare; usually means /Library is
/// missing or the user has no home directory).
bool scan(QVector<PersistenceItem>& out, int& errorsLogged);

}  // namespace PersistenceScanner
