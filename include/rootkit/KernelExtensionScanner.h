#pragma once
// ============================================================================
// KernelExtensionScanner.h  –  Phase 3: enumerate kernel/system extensions
//
// Sources used (all unprivileged on macOS):
//   • /usr/bin/systemextensionsctl list   – modern macOS extension model
//   • /usr/bin/kmutil showloaded          – legacy kexts (still present on
//                                            x86_64 hosts; fewer on Apple
//                                            Silicon by design)
//   • /proc/modules                       – Linux kernel modules
//
// Why this matters for rootkit awareness:
//   The kernel-resident code on a system is the highest-trust layer. If an
//   attacker gets a kernel module loaded — or hijacks a legitimate one's
//   slot — they have effectively unlimited capability. We can't validate
//   the kernel from userspace, but we CAN enumerate what's loaded and flag
//   anything not signed by Apple (or by the user's well-known team IDs).
//
// What's flagged as suspicious by default:
//   • severity=high  : extension with no team ID
//   • severity=high  : signed-by string contains "ad hoc" or "unsigned"
//   • severity=medium: non-Apple team ID we've never seen before
//   • severity=low   : Apple-signed (always — but listed for visibility)
// ============================================================================

#include "rootkit/RootkitTypes.h"

namespace KernelExtensionScanner {

/// Enumerate every loaded kext / system extension.
///
/// out          – appended findings
/// totalsOut    – total count (for the UI KPI tile)
/// Returns true if at least one source produced parseable output.
bool list(QVector<KernelExtension>& out, int& totalsOut);

}  // namespace KernelExtensionScanner
